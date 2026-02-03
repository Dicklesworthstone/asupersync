//! RaptorQ inactivation decoder with deterministic pivoting.
//!
//! Implements a two-phase decoding strategy:
//! 1. **Peeling**: Iteratively solve degree-1 equations (belief propagation)
//! 2. **Inactivation**: Mark stubborn symbols as inactive, defer to Gaussian elimination
//!
//! # Determinism
//!
//! All operations are deterministic:
//! - Pivot selection uses stable lexicographic ordering
//! - Tie-breaking rules are explicit (lowest column index wins)
//! - Same received symbols in same order produce identical decode results

use crate::raptorq::gf256::{gf256_addmul_slice, Gf256};
use crate::raptorq::proof::{
    DecodeConfig, DecodeProof, EliminationTrace, FailureReason, PeelingTrace, ReceivedSummary,
};
use crate::raptorq::systematic::{RobustSoliton, SystematicParams};
use crate::types::ObjectId;
use crate::util::DetRng;

use std::collections::BTreeSet;

// ============================================================================
// Decoder types
// ============================================================================

/// A received symbol (source or repair) with its equation.
#[derive(Debug, Clone)]
pub struct ReceivedSymbol {
    /// Encoding Symbol Index (ESI).
    pub esi: u32,
    /// Whether this is a source symbol (ESI < K).
    pub is_source: bool,
    /// Column indices that this symbol depends on (intermediate symbol indices).
    /// For source symbols, this is just `[esi]`. For repair, computed from LT encoding.
    pub columns: Vec<usize>,
    /// GF(256) coefficients for each column (same length as `columns`).
    /// For XOR-based LT, all coefficients are 1.
    pub coefficients: Vec<Gf256>,
    /// The symbol data.
    pub data: Vec<u8>,
}

/// Reason for decode failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecodeError {
    /// Not enough symbols received to solve the system.
    InsufficientSymbols {
        /// Number of symbols received.
        received: usize,
        /// Minimum required (L = K + S + H).
        required: usize,
    },
    /// Matrix became singular during Gaussian elimination.
    SingularMatrix {
        /// Row that couldn't find a pivot.
        row: usize,
    },
    /// Symbol size mismatch.
    SymbolSizeMismatch {
        /// Expected size.
        expected: usize,
        /// Actual size found.
        actual: usize,
    },
}

/// Decode statistics for observability.
#[derive(Debug, Clone, Default)]
pub struct DecodeStats {
    /// Symbols solved via peeling (degree-1 propagation).
    pub peeled: usize,
    /// Symbols marked as inactive.
    pub inactivated: usize,
    /// Gaussian elimination row operations performed.
    pub gauss_ops: usize,
    /// Total pivot selections made.
    pub pivots_selected: usize,
}

/// Result of successful decoding.
#[derive(Debug)]
pub struct DecodeResult {
    /// Recovered intermediate symbols (L symbols).
    pub intermediate: Vec<Vec<u8>>,
    /// Recovered source symbols (first K of intermediate).
    pub source: Vec<Vec<u8>>,
    /// Decode statistics.
    pub stats: DecodeStats,
}

/// Result of decoding with proof artifact.
#[derive(Debug)]
pub struct DecodeResultWithProof {
    /// The decode result (success case).
    pub result: DecodeResult,
    /// Proof artifact explaining the decode process.
    pub proof: DecodeProof,
}

// ============================================================================
// Decoder state
// ============================================================================

/// Internal decoder state during the decode process.
struct DecoderState {
    /// Encoding parameters.
    params: SystematicParams,
    /// Received equations (row-major, each row is an equation).
    equations: Vec<Equation>,
    /// Right-hand side data for each equation.
    rhs: Vec<Vec<u8>>,
    /// Solved intermediate symbols (None if not yet solved).
    solved: Vec<Option<Vec<u8>>>,
    /// Set of active (unsolved, not inactivated) columns.
    active_cols: BTreeSet<usize>,
    /// Set of inactivated columns (will be solved via Gaussian elimination).
    inactive_cols: BTreeSet<usize>,
    /// Statistics.
    stats: DecodeStats,
}

/// A sparse equation over GF(256).
#[derive(Debug, Clone)]
struct Equation {
    /// (column_index, coefficient) pairs, sorted by column index.
    terms: Vec<(usize, Gf256)>,
    /// Whether this equation has been used (solved or eliminated).
    used: bool,
}

impl Equation {
    fn new(columns: Vec<usize>, coefficients: Vec<Gf256>) -> Self {
        let mut terms: Vec<_> = columns.into_iter().zip(coefficients).collect();
        // Sort by column index for deterministic ordering
        terms.sort_by_key(|(col, _)| *col);
        // Merge duplicates (XOR coefficients)
        let mut merged = Vec::with_capacity(terms.len());
        for (col, coef) in terms {
            if let Some((last_col, last_coef)) = merged.last_mut() {
                if *last_col == col {
                    *last_coef += coef;
                    continue;
                }
            }
            merged.push((col, coef));
        }
        // Remove zero coefficients
        merged.retain(|(_, coef)| !coef.is_zero());
        Self {
            terms: merged,
            used: false,
        }
    }

    /// Returns the degree (number of nonzero terms).
    fn degree(&self) -> usize {
        self.terms.len()
    }

    /// Returns the lowest column index (pivot candidate).
    fn lowest_col(&self) -> Option<usize> {
        self.terms.first().map(|(col, _)| *col)
    }

    /// Returns the coefficient for the given column, or zero.
    fn coef(&self, col: usize) -> Gf256 {
        self.terms
            .binary_search_by_key(&col, |(c, _)| *c)
            .map(|idx| self.terms[idx].1)
            .unwrap_or(Gf256::ZERO)
    }

    /// Substitute: eliminate `col` using `pivot_coef * pivot_rhs`.
    fn eliminate(&mut self, _col: usize, pivot_terms: &[(usize, Gf256)], factor: Gf256) {
        // self -= factor * pivot (for the column `col`)
        // This effectively does: self.terms = self.terms XOR (factor * pivot.terms)
        // but only for terms that would affect our equation.

        // Build new terms by merging
        let mut new_terms = Vec::with_capacity(self.terms.len() + pivot_terms.len());
        let mut i = 0;
        let mut j = 0;

        while i < self.terms.len() || j < pivot_terms.len() {
            let self_col = self.terms.get(i).map_or(usize::MAX, |(c, _)| *c);
            let pivot_col = pivot_terms.get(j).map_or(usize::MAX, |(c, _)| *c);

            match self_col.cmp(&pivot_col) {
                std::cmp::Ordering::Less => {
                    new_terms.push(self.terms[i]);
                    i += 1;
                }
                std::cmp::Ordering::Greater => {
                    let (c, coef) = pivot_terms[j];
                    new_terms.push((c, factor * coef));
                    j += 1;
                }
                std::cmp::Ordering::Equal => {
                    let self_coef = self.terms[i].1;
                    let pivot_coef = pivot_terms[j].1;
                    let new_coef = self_coef + factor * pivot_coef;
                    if !new_coef.is_zero() {
                        new_terms.push((self_col, new_coef));
                    }
                    i += 1;
                    j += 1;
                }
            }
        }

        self.terms = new_terms;
    }
}

// ============================================================================
// Inactivation decoder
// ============================================================================

/// Inactivation decoder for RaptorQ.
///
/// Decodes received symbols (source or repair) to recover intermediate
/// symbols, then extracts the original source data.
pub struct InactivationDecoder {
    params: SystematicParams,
    soliton: RobustSoliton,
    seed: u64,
}

impl InactivationDecoder {
    /// Create a new decoder for the given parameters.
    #[must_use]
    pub fn new(k: usize, symbol_size: usize, seed: u64) -> Self {
        let params = SystematicParams::for_source_block(k, symbol_size);
        let soliton = RobustSoliton::new(params.l, 0.2, 0.05);
        Self {
            params,
            soliton,
            seed,
        }
    }

    /// Returns the encoding parameters.
    #[must_use]
    pub const fn params(&self) -> &SystematicParams {
        &self.params
    }

    /// Decode from received symbols.
    ///
    /// `symbols` should contain at least `L` symbols (K source + S LDPC + H HDPC overhead).
    /// Returns the decoded source symbols on success.
    pub fn decode(&self, symbols: &[ReceivedSymbol]) -> Result<DecodeResult, DecodeError> {
        let l = self.params.l;
        let k = self.params.k;
        let symbol_size = self.params.symbol_size;

        // Validate input
        if symbols.len() < l {
            return Err(DecodeError::InsufficientSymbols {
                received: symbols.len(),
                required: l,
            });
        }

        for sym in symbols {
            if sym.data.len() != symbol_size {
                return Err(DecodeError::SymbolSizeMismatch {
                    expected: symbol_size,
                    actual: sym.data.len(),
                });
            }
        }

        // Build decoder state
        let mut state = self.build_state(symbols);

        // Phase 1: Peeling
        Self::peel(&mut state);

        // Phase 2: Inactivation + Gaussian elimination
        self.inactivate_and_solve(&mut state)?;

        // Extract results
        let intermediate: Vec<Vec<u8>> = state
            .solved
            .into_iter()
            .map(|opt| opt.unwrap_or_else(|| vec![0u8; symbol_size]))
            .collect();

        let source: Vec<Vec<u8>> = intermediate[..k].to_vec();

        Ok(DecodeResult {
            intermediate,
            source,
            stats: state.stats,
        })
    }

    /// Decode from received symbols with proof artifact capture.
    ///
    /// Like `decode`, but also captures a proof artifact that explains
    /// the decode process for debugging and verification.
    ///
    /// # Arguments
    ///
    /// * `symbols` - Received symbols (at least L required)
    /// * `object_id` - Object ID for the proof artifact
    /// * `sbn` - Source block number for the proof artifact
    #[allow(clippy::result_large_err)]
    pub fn decode_with_proof(
        &self,
        symbols: &[ReceivedSymbol],
        object_id: ObjectId,
        sbn: u8,
    ) -> Result<DecodeResultWithProof, (DecodeError, DecodeProof)> {
        let l = self.params.l;
        let k = self.params.k;
        let symbol_size = self.params.symbol_size;

        // Build proof configuration
        let config = DecodeConfig {
            object_id,
            sbn,
            k,
            s: self.params.s,
            h: self.params.h,
            l,
            symbol_size,
            seed: self.seed,
        };
        let mut proof_builder = DecodeProof::builder(config);

        // Capture received symbols summary
        let received = ReceivedSummary::from_received(symbols.iter().map(|s| (s.esi, s.is_source)));
        proof_builder.set_received(received);

        // Validate input
        if symbols.len() < l {
            let err = DecodeError::InsufficientSymbols {
                received: symbols.len(),
                required: l,
            };
            proof_builder.set_failure(FailureReason::from(&err));
            return Err((err, proof_builder.build()));
        }

        for sym in symbols {
            if sym.data.len() != symbol_size {
                let err = DecodeError::SymbolSizeMismatch {
                    expected: symbol_size,
                    actual: sym.data.len(),
                };
                proof_builder.set_failure(FailureReason::from(&err));
                return Err((err, proof_builder.build()));
            }
        }

        // Build decoder state
        let mut state = self.build_state(symbols);

        // Phase 1: Peeling with proof capture
        Self::peel_with_proof(&mut state, proof_builder.peeling_mut());

        // Phase 2: Inactivation + Gaussian elimination with proof capture
        if let Err(err) =
            self.inactivate_and_solve_with_proof(&mut state, proof_builder.elimination_mut())
        {
            proof_builder.set_failure(FailureReason::from(&err));
            return Err((err, proof_builder.build()));
        }

        // Extract results
        let intermediate: Vec<Vec<u8>> = state
            .solved
            .into_iter()
            .map(|opt| opt.unwrap_or_else(|| vec![0u8; symbol_size]))
            .collect();

        let source: Vec<Vec<u8>> = intermediate[..k].to_vec();

        // Mark success
        proof_builder.set_success(k);

        Ok(DecodeResultWithProof {
            result: DecodeResult {
                intermediate,
                source,
                stats: state.stats,
            },
            proof: proof_builder.build(),
        })
    }

    /// Build initial decoder state from received symbols.
    ///
    /// Includes LDPC and HDPC constraint equations (with zero RHS) in addition
    /// to the received symbol equations. These constraints tie together the
    /// intermediate symbols and are essential for successful decoding.
    fn build_state(&self, symbols: &[ReceivedSymbol]) -> DecoderState {
        let l = self.params.l;
        let s = self.params.s;
        let h = self.params.h;
        let symbol_size = self.params.symbol_size;

        // Capacity: LDPC (S) + HDPC (H) + received symbols
        let total_eqs = s + h + symbols.len();
        let mut equations = Vec::with_capacity(total_eqs);
        let mut rhs = Vec::with_capacity(total_eqs);

        // Add LDPC constraint equations (S equations with zero RHS)
        let ldpc_eqs = self.build_ldpc_constraints();
        for eq in ldpc_eqs {
            equations.push(eq);
            rhs.push(vec![0u8; symbol_size]);
        }

        // Add HDPC constraint equations (H equations with zero RHS)
        let hdpc_eqs = self.build_hdpc_constraints();
        for eq in hdpc_eqs {
            equations.push(eq);
            rhs.push(vec![0u8; symbol_size]);
        }

        // Add received symbol equations
        for sym in symbols {
            let eq = Equation::new(sym.columns.clone(), sym.coefficients.clone());
            equations.push(eq);
            rhs.push(sym.data.clone());
        }

        let active_cols: BTreeSet<usize> = (0..l).collect();

        DecoderState {
            params: self.params.clone(),
            equations,
            rhs,
            solved: vec![None; l],
            active_cols,
            inactive_cols: BTreeSet::new(),
            stats: DecodeStats::default(),
        }
    }

    /// Build LDPC constraint equations.
    ///
    /// These are the same constraints used by the encoder in `build_ldpc_rows`.
    /// Each LDPC row connects a few intermediate symbols with XOR (GF(2)).
    fn build_ldpc_constraints(&self) -> Vec<Equation> {
        let s = self.params.s;
        let l = self.params.l;

        // Build sparse representation for each LDPC row
        let mut row_terms: Vec<Vec<(usize, Gf256)>> = vec![Vec::new(); s];

        // Each intermediate symbol i participates in LDPC rows
        // (i % S), ((i / S) % S)
        for i in 0..l {
            let r0 = i % s;
            let r1 = (i / s.max(1)) % s;
            row_terms[r0].push((i, Gf256::ONE));
            if r0 != r1 {
                row_terms[r1].push((i, Gf256::ONE));
            }
        }

        // Additional LDPC connections using seed-derived pattern
        let mut rng = DetRng::new(self.seed.wrapping_add(0x1D9C_1D9C_0000));
        for terms in row_terms.iter_mut().take(s) {
            let extra = 1 + rng.next_usize(2); // 1-2 additional connections
            for _ in 0..extra {
                let col = rng.next_usize(l);
                terms.push((col, Gf256::ONE));
            }
        }

        // Convert to Equations
        row_terms
            .into_iter()
            .map(|terms| {
                let (cols, coefs): (Vec<_>, Vec<_>) = terms.into_iter().unzip();
                Equation::new(cols, coefs)
            })
            .collect()
    }

    /// Build HDPC constraint equations.
    ///
    /// These are the same constraints used by the encoder in `build_hdpc_rows`.
    /// HDPC rows use GF(256) coefficients (not just GF(2)) to provide
    /// half-distance parity coverage.
    fn build_hdpc_constraints(&self) -> Vec<Equation> {
        let h = self.params.h;
        let l = self.params.l;

        let mut equations = Vec::with_capacity(h);
        let mut rng = DetRng::new(self.seed.wrapping_add(0x4D9C_4D9C_0000));

        for row_offset in 0..h {
            let alpha_pow = Gf256::ALPHA.pow((row_offset & 0xFF) as u8);
            let mut coeff_acc = Gf256::ONE;
            let mut cols = Vec::with_capacity(l);
            let mut coefficients = Vec::with_capacity(l);

            for col in 0..l {
                // Mix structured (Vandermonde) and random components
                let random_part = Gf256::new(rng.next_u64() as u8);
                let c = coeff_acc + random_part;
                if !c.is_zero() {
                    cols.push(col);
                    coefficients.push(c);
                }
                coeff_acc *= alpha_pow;
            }

            equations.push(Equation::new(cols, coefficients));
        }

        equations
    }

    /// Phase 1: Peeling (belief propagation).
    ///
    /// Find degree-1 equations and solve them, propagating the solution
    /// to other equations.
    fn peel(state: &mut DecoderState) {
        loop {
            // Find an unused degree-1 equation with an active column
            let deg1_idx = state.equations.iter().enumerate().find_map(|(idx, eq)| {
                if eq.used || eq.degree() != 1 {
                    return None;
                }
                let col = eq.terms[0].0;
                if state.active_cols.contains(&col) && state.solved[col].is_none() {
                    Some(idx)
                } else {
                    None
                }
            });

            let Some(eq_idx) = deg1_idx else {
                break;
            };

            // Solve this equation
            let (col, coef) = state.equations[eq_idx].terms[0];
            state.equations[eq_idx].used = true;

            // Compute the solution: intermediate[col] = rhs[eq_idx] / coef
            let mut solution = state.rhs[eq_idx].clone();
            if coef != Gf256::ONE {
                let inv = coef.inv();
                crate::raptorq::gf256::gf256_mul_slice(&mut solution, inv);
            }

            state.solved[col] = Some(solution.clone());
            state.active_cols.remove(&col);
            state.stats.peeled += 1;

            // Propagate to other equations: subtract col's contribution
            for (i, eq) in state.equations.iter_mut().enumerate() {
                if eq.used {
                    continue;
                }
                let eq_coef = eq.coef(col);
                if eq_coef.is_zero() {
                    continue;
                }
                // rhs[i] -= eq_coef * solution
                gf256_addmul_slice(&mut state.rhs[i], &solution, eq_coef);
                // Remove the term from the equation
                eq.terms.retain(|(c, _)| *c != col);
            }
        }
    }

    /// Phase 1: Peeling with proof trace capture.
    ///
    /// Like `peel`, but also records solved symbols to the proof trace.
    fn peel_with_proof(state: &mut DecoderState, trace: &mut PeelingTrace) {
        loop {
            // Find an unused degree-1 equation with an active column
            let deg1_idx = state.equations.iter().enumerate().find_map(|(idx, eq)| {
                if eq.used || eq.degree() != 1 {
                    return None;
                }
                let col = eq.terms[0].0;
                if state.active_cols.contains(&col) && state.solved[col].is_none() {
                    Some(idx)
                } else {
                    None
                }
            });

            let Some(eq_idx) = deg1_idx else {
                break;
            };

            // Solve this equation
            let (col, coef) = state.equations[eq_idx].terms[0];
            state.equations[eq_idx].used = true;

            // Compute the solution: intermediate[col] = rhs[eq_idx] / coef
            let mut solution = state.rhs[eq_idx].clone();
            if coef != Gf256::ONE {
                let inv = coef.inv();
                crate::raptorq::gf256::gf256_mul_slice(&mut solution, inv);
            }

            state.solved[col] = Some(solution.clone());
            state.active_cols.remove(&col);
            state.stats.peeled += 1;

            // Record in proof trace
            trace.record_solved(col);

            // Propagate to other equations: subtract col's contribution
            for (i, eq) in state.equations.iter_mut().enumerate() {
                if eq.used {
                    continue;
                }
                let eq_coef = eq.coef(col);
                if eq_coef.is_zero() {
                    continue;
                }
                // rhs[i] -= eq_coef * solution
                gf256_addmul_slice(&mut state.rhs[i], &solution, eq_coef);
                // Remove the term from the equation
                eq.terms.retain(|(c, _)| *c != col);
            }
        }
    }

    /// Phase 2: Inactivation + Gaussian elimination.
    fn inactivate_and_solve(&self, state: &mut DecoderState) -> Result<(), DecodeError> {
        let symbol_size = self.params.symbol_size;

        // Collect remaining unsolved columns
        let unsolved: Vec<usize> = state
            .active_cols
            .iter()
            .filter(|&&col| state.solved[col].is_none())
            .copied()
            .collect();

        if unsolved.is_empty() {
            return Ok(());
        }

        // Collect unused equations
        let unused_eqs: Vec<usize> = state
            .equations
            .iter()
            .enumerate()
            .filter_map(|(i, eq)| if eq.used { None } else { Some(i) })
            .collect();

        // Mark all remaining unsolved columns as inactive
        for &col in &unsolved {
            state.inactive_cols.insert(col);
            state.active_cols.remove(&col);
            state.stats.inactivated += 1;
        }

        // Build dense submatrix for Gaussian elimination
        // Rows = unused equations, Columns = unsolved columns
        let n_rows = unused_eqs.len();
        let n_cols = unsolved.len();

        if n_rows < n_cols {
            return Err(DecodeError::InsufficientSymbols {
                received: n_rows,
                required: n_cols,
            });
        }

        // Column index mapping: unsolved column -> dense index
        let col_to_dense: std::collections::HashMap<usize, usize> =
            unsolved.iter().enumerate().map(|(i, &c)| (c, i)).collect();

        // Build dense matrix A and RHS vector b
        let mut a = vec![vec![Gf256::ZERO; n_cols]; n_rows];
        let mut b: Vec<Vec<u8>> = Vec::with_capacity(n_rows);

        for (row, &eq_idx) in unused_eqs.iter().enumerate() {
            for &(col, coef) in &state.equations[eq_idx].terms {
                if let Some(&dense_col) = col_to_dense.get(&col) {
                    a[row][dense_col] = coef;
                }
            }
            b.push(state.rhs[eq_idx].clone());
        }

        // Gaussian elimination with partial pivoting
        let mut pivot_row = vec![usize::MAX; n_cols];

        for col in 0..n_cols {
            // Find pivot: first nonzero in column `col` among unassigned rows
            let pivot = (0..n_rows)
                .find(|&row| pivot_row.iter().all(|&pr| pr != row) && !a[row][col].is_zero());

            let Some(prow) = pivot else {
                return Err(DecodeError::SingularMatrix { row: col });
            };

            pivot_row[col] = prow;
            state.stats.pivots_selected += 1;

            // Scale pivot row so a[prow][col] = 1
            let pivot_coef = a[prow][col];
            let inv = pivot_coef.inv();
            for value in &mut a[prow] {
                *value *= inv;
            }
            crate::raptorq::gf256::gf256_mul_slice(&mut b[prow], inv);

            // Eliminate column in all other rows
            // Clone pivot row to avoid borrow conflict
            let pivot_row_data: Vec<Gf256> = a[prow].clone();
            let pivot_rhs = b[prow].clone();
            for row in 0..n_rows {
                if row == prow {
                    continue;
                }
                let factor = a[row][col];
                if factor.is_zero() {
                    continue;
                }
                for c in 0..n_cols {
                    a[row][c] += factor * pivot_row_data[c];
                }
                gf256_addmul_slice(&mut b[row], &pivot_rhs, factor);
                state.stats.gauss_ops += 1;
            }
        }

        // Extract solutions
        for (dense_col, &col) in unsolved.iter().enumerate() {
            let prow = pivot_row[dense_col];
            if prow < n_rows {
                state.solved[col] = Some(b[prow].clone());
            } else {
                state.solved[col] = Some(vec![0u8; symbol_size]);
            }
        }

        Ok(())
    }

    /// Phase 2: Inactivation + Gaussian elimination with proof trace capture.
    ///
    /// Like `inactivate_and_solve`, but also records inactivations, pivots,
    /// and row operations to the proof trace.
    fn inactivate_and_solve_with_proof(
        &self,
        state: &mut DecoderState,
        trace: &mut EliminationTrace,
    ) -> Result<(), DecodeError> {
        let symbol_size = self.params.symbol_size;

        // Collect remaining unsolved columns
        let unsolved: Vec<usize> = state
            .active_cols
            .iter()
            .filter(|&&col| state.solved[col].is_none())
            .copied()
            .collect();

        if unsolved.is_empty() {
            return Ok(());
        }

        // Collect unused equations
        let unused_eqs: Vec<usize> = state
            .equations
            .iter()
            .enumerate()
            .filter_map(|(i, eq)| if eq.used { None } else { Some(i) })
            .collect();

        // Mark all remaining unsolved columns as inactive
        for &col in &unsolved {
            state.inactive_cols.insert(col);
            state.active_cols.remove(&col);
            state.stats.inactivated += 1;
            // Record inactivation in proof trace
            trace.record_inactivation(col);
        }

        // Build dense submatrix for Gaussian elimination
        // Rows = unused equations, Columns = unsolved columns
        let n_rows = unused_eqs.len();
        let n_cols = unsolved.len();

        if n_rows < n_cols {
            return Err(DecodeError::InsufficientSymbols {
                received: n_rows,
                required: n_cols,
            });
        }

        // Column index mapping: unsolved column -> dense index
        let col_to_dense: std::collections::HashMap<usize, usize> =
            unsolved.iter().enumerate().map(|(i, &c)| (c, i)).collect();

        // Build dense matrix A and RHS vector b
        let mut a = vec![vec![Gf256::ZERO; n_cols]; n_rows];
        let mut b: Vec<Vec<u8>> = Vec::with_capacity(n_rows);

        for (row, &eq_idx) in unused_eqs.iter().enumerate() {
            for &(col, coef) in &state.equations[eq_idx].terms {
                if let Some(&dense_col) = col_to_dense.get(&col) {
                    a[row][dense_col] = coef;
                }
            }
            b.push(state.rhs[eq_idx].clone());
        }

        // Gaussian elimination with partial pivoting
        let mut pivot_row = vec![usize::MAX; n_cols];

        for col in 0..n_cols {
            // Find pivot: first nonzero in column `col` among unassigned rows
            let pivot = (0..n_rows)
                .find(|&row| pivot_row.iter().all(|&pr| pr != row) && !a[row][col].is_zero());

            let Some(prow) = pivot else {
                return Err(DecodeError::SingularMatrix { row: col });
            };

            pivot_row[col] = prow;
            state.stats.pivots_selected += 1;
            // Record pivot in proof trace (use original column index)
            trace.record_pivot(unsolved[col], prow);

            // Scale pivot row so a[prow][col] = 1
            let pivot_coef = a[prow][col];
            let inv = pivot_coef.inv();
            for value in &mut a[prow] {
                *value *= inv;
            }
            crate::raptorq::gf256::gf256_mul_slice(&mut b[prow], inv);

            // Eliminate column in all other rows
            // Clone pivot row to avoid borrow conflict
            let pivot_row_data: Vec<Gf256> = a[prow].clone();
            let pivot_rhs = b[prow].clone();
            for row in 0..n_rows {
                if row == prow {
                    continue;
                }
                let factor = a[row][col];
                if factor.is_zero() {
                    continue;
                }
                for c in 0..n_cols {
                    a[row][c] += factor * pivot_row_data[c];
                }
                gf256_addmul_slice(&mut b[row], &pivot_rhs, factor);
                state.stats.gauss_ops += 1;
                // Record row operation in proof trace
                trace.record_row_op();
            }
        }

        // Extract solutions
        for (dense_col, &col) in unsolved.iter().enumerate() {
            let prow = pivot_row[dense_col];
            if prow < n_rows {
                state.solved[col] = Some(b[prow].clone());
            } else {
                state.solved[col] = Some(vec![0u8; symbol_size]);
            }
        }

        Ok(())
    }

    /// Generate the equation (columns + coefficients) for a repair symbol.
    ///
    /// This reconstructs the LT encoding pattern for the given ESI.
    #[must_use]
    pub fn repair_equation(&self, esi: u32) -> (Vec<usize>, Vec<Gf256>) {
        let l = self.params.l;

        let sym_seed = self
            .seed
            .wrapping_mul(0x9E37_79B9_7F4A_7C15)
            .wrapping_add(u64::from(esi));
        let mut rng = DetRng::new(sym_seed);

        let degree = self.soliton.sample(rng.next_u64() as u32);

        let mut columns = Vec::with_capacity(degree);
        let mut coefficients = Vec::with_capacity(degree);

        for _ in 0..degree {
            let idx = rng.next_usize(l);
            columns.push(idx);
            coefficients.push(Gf256::ONE); // XOR-based LT uses coefficient 1
        }

        (columns, coefficients)
    }
}

// ============================================================================
// Helper: build ReceivedSymbol from raw data
// ============================================================================

impl ReceivedSymbol {
    /// Create a source symbol (ESI < K).
    #[must_use]
    pub fn source(esi: u32, data: Vec<u8>) -> Self {
        Self {
            esi,
            is_source: true,
            columns: vec![esi as usize],
            coefficients: vec![Gf256::ONE],
            data,
        }
    }

    /// Create a repair symbol with precomputed equation.
    #[must_use]
    pub fn repair(esi: u32, columns: Vec<usize>, coefficients: Vec<Gf256>, data: Vec<u8>) -> Self {
        Self {
            esi,
            is_source: false,
            columns,
            coefficients,
            data,
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::raptorq::systematic::SystematicEncoder;

    fn make_source_data(k: usize, symbol_size: usize) -> Vec<Vec<u8>> {
        (0..k)
            .map(|i| {
                (0..symbol_size)
                    .map(|j| ((i * 37 + j * 13 + 7) % 256) as u8)
                    .collect()
            })
            .collect()
    }

    #[test]
    fn decode_all_source_symbols() {
        let k = 8;
        let symbol_size = 32;
        let seed = 42u64;

        let source = make_source_data(k, symbol_size);
        let decoder = InactivationDecoder::new(k, symbol_size, seed);

        // Receive all source symbols
        let mut received: Vec<ReceivedSymbol> = source
            .iter()
            .enumerate()
            .map(|(i, data)| ReceivedSymbol::source(i as u32, data.clone()))
            .collect();

        // Add some repair symbols to reach L
        let encoder = SystematicEncoder::new(&source, symbol_size, seed).unwrap();
        let l = decoder.params().l;
        for esi in (k as u32)..(l as u32) {
            let (cols, coefs) = decoder.repair_equation(esi);
            let repair_data = encoder.repair_symbol(esi);
            received.push(ReceivedSymbol::repair(esi, cols, coefs, repair_data));
        }

        let result = decoder.decode(&received).expect("decode should succeed");

        // Verify source symbols match
        for (i, original) in source.iter().enumerate() {
            assert_eq!(&result.source[i], original, "source symbol {i} mismatch");
        }
    }

    #[test]
    fn decode_mixed_source_and_repair() {
        let k = 8;
        let symbol_size = 32;
        let seed = 42u64;

        let source = make_source_data(k, symbol_size);
        let encoder = SystematicEncoder::new(&source, symbol_size, seed).unwrap();
        let decoder = InactivationDecoder::new(k, symbol_size, seed);
        let l = decoder.params().l;

        // Receive half source, half repair
        let mut received = Vec::new();

        // First half source symbols
        for i in 0..(k / 2) {
            received.push(ReceivedSymbol::source(i as u32, source[i].clone()));
        }

        // Fill with repair symbols
        for esi in (k as u32)..(l as u32 + k as u32 / 2) {
            let (cols, coefs) = decoder.repair_equation(esi);
            let repair_data = encoder.repair_symbol(esi);
            received.push(ReceivedSymbol::repair(esi, cols, coefs, repair_data));
        }

        let result = decoder.decode(&received).expect("decode should succeed");

        for (i, original) in source.iter().enumerate() {
            assert_eq!(&result.source[i], original, "source symbol {i} mismatch");
        }
    }

    #[test]
    fn decode_repair_only() {
        let k = 4;
        let symbol_size = 16;
        let seed = 99u64;

        let source = make_source_data(k, symbol_size);
        let encoder = SystematicEncoder::new(&source, symbol_size, seed).unwrap();
        let decoder = InactivationDecoder::new(k, symbol_size, seed);
        let l = decoder.params().l;

        // Receive only repair symbols (need at least L)
        let mut received = Vec::new();
        for esi in (k as u32)..(k as u32 + l as u32) {
            let (cols, coefs) = decoder.repair_equation(esi);
            let repair_data = encoder.repair_symbol(esi);
            received.push(ReceivedSymbol::repair(esi, cols, coefs, repair_data));
        }

        let result = decoder.decode(&received).expect("decode should succeed");

        for (i, original) in source.iter().enumerate() {
            assert_eq!(&result.source[i], original, "source symbol {i} mismatch");
        }
    }

    #[test]
    fn decode_insufficient_symbols_fails() {
        let k = 8;
        let symbol_size = 32;
        let seed = 42u64;

        let source = make_source_data(k, symbol_size);
        let decoder = InactivationDecoder::new(k, symbol_size, seed);
        let l = decoder.params().l;

        // Receive fewer than L symbols
        let received: Vec<ReceivedSymbol> = source[..l - 1]
            .iter()
            .enumerate()
            .map(|(i, data)| ReceivedSymbol::source(i as u32, data.clone()))
            .collect();

        let err = decoder.decode(&received).unwrap_err();
        assert!(matches!(err, DecodeError::InsufficientSymbols { .. }));
    }

    #[test]
    fn decode_deterministic() {
        let k = 6;
        let symbol_size = 24;
        let seed = 77u64;

        let source = make_source_data(k, symbol_size);
        let encoder = SystematicEncoder::new(&source, symbol_size, seed).unwrap();
        let decoder = InactivationDecoder::new(k, symbol_size, seed);
        let l = decoder.params().l;

        // Build received symbols
        let mut received: Vec<ReceivedSymbol> = source
            .iter()
            .enumerate()
            .map(|(i, data)| ReceivedSymbol::source(i as u32, data.clone()))
            .collect();

        for esi in (k as u32)..(l as u32) {
            let (cols, coefs) = decoder.repair_equation(esi);
            let repair_data = encoder.repair_symbol(esi);
            received.push(ReceivedSymbol::repair(esi, cols, coefs, repair_data));
        }

        // Decode twice
        let result1 = decoder.decode(&received).unwrap();
        let result2 = decoder.decode(&received).unwrap();

        // Results must be identical
        assert_eq!(result1.source, result2.source);
        assert_eq!(result1.stats.peeled, result2.stats.peeled);
        assert_eq!(result1.stats.inactivated, result2.stats.inactivated);
    }

    #[test]
    fn stats_track_peeling_and_inactivation() {
        let k = 4;
        let symbol_size = 16;
        let seed = 123u64;

        let source = make_source_data(k, symbol_size);
        let decoder = InactivationDecoder::new(k, symbol_size, seed);

        // All source symbols should allow peeling
        let mut received: Vec<ReceivedSymbol> = source
            .iter()
            .enumerate()
            .map(|(i, data)| ReceivedSymbol::source(i as u32, data.clone()))
            .collect();

        // Add zero-data equations for LDPC/HDPC
        let l = decoder.params().l;
        for col in k..l {
            received.push(ReceivedSymbol {
                esi: col as u32,
                is_source: false,
                columns: vec![col],
                coefficients: vec![Gf256::ONE],
                data: vec![0u8; symbol_size],
            });
        }

        let result = decoder.decode(&received).unwrap();

        // At least some peeling should occur
        assert!(result.stats.peeled > 0, "expected some peeling");
    }
}
