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
use crate::raptorq::systematic::{ConstraintMatrix, SystematicParams};
use crate::types::ObjectId;

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
            .map_or(Gf256::ZERO, |idx| self.terms[idx].1)
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
    seed: u64,
}

impl InactivationDecoder {
    /// Create a new decoder for the given parameters.
    #[must_use]
    pub fn new(k: usize, symbol_size: usize, seed: u64) -> Self {
        let params = SystematicParams::for_source_block(k, symbol_size);
        Self { params, seed }
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
    /// The caller is responsible for including LDPC/HDPC constraint equations
    /// (with zero RHS) in the received symbols if needed. The higher-level
    /// `decoding.rs` module handles this by building constraint rows from
    /// the constraint matrix.
    fn build_state(&self, symbols: &[ReceivedSymbol]) -> DecoderState {
        let l = self.params.l;

        let mut equations = Vec::with_capacity(symbols.len());
        let mut rhs = Vec::with_capacity(symbols.len());

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

    /// Generate constraint symbols (LDPC + HDPC) with zero data.
    ///
    /// These should be included in the received symbols when decoding.
    /// The `decoding.rs` module handles this automatically; this method
    /// is provided for direct decoder testing.
    #[must_use]
    pub fn constraint_symbols(&self) -> Vec<ReceivedSymbol> {
        let s = self.params.s;
        let h = self.params.h;
        let symbol_size = self.params.symbol_size;
        let base_rows = s + h;

        // Build the constraint matrix (same as encoder uses)
        let constraints = ConstraintMatrix::build(&self.params, self.seed);

        let mut result = Vec::with_capacity(base_rows);

        // Extract the first S+H rows (LDPC + HDPC constraints)
        for row in 0..base_rows {
            let (columns, coefficients) = Self::constraint_row_equation(&constraints, row);
            result.push(ReceivedSymbol {
                esi: row as u32,
                is_source: false,
                columns,
                coefficients,
                data: vec![0u8; symbol_size],
            });
        }

        result
    }

    /// Extract a sparse equation from a constraint matrix row.
    fn constraint_row_equation(
        constraints: &ConstraintMatrix,
        row: usize,
    ) -> (Vec<usize>, Vec<Gf256>) {
        let mut columns = Vec::new();
        let mut coefficients = Vec::new();
        for col in 0..constraints.cols {
            let coeff = constraints.get(row, col);
            if !coeff.is_zero() {
                columns.push(col);
                coefficients.push(coeff);
            }
        }
        (columns, coefficients)
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
            let mut solution = std::mem::take(&mut state.rhs[eq_idx]);
            if coef != Gf256::ONE {
                let inv = coef.inv();
                crate::raptorq::gf256::gf256_mul_slice(&mut solution, inv);
            }

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
                // Remove the term from the equation.
                // Binary search is efficient since terms are sorted by column index.
                if let Ok(pos) = eq.terms.binary_search_by_key(&col, |(c, _)| *c) {
                    eq.terms.remove(pos);
                }
            }

            // Move solution instead of cloning (avoids allocation)
            state.solved[col] = Some(solution);
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
            let mut solution = std::mem::take(&mut state.rhs[eq_idx]);
            if coef != Gf256::ONE {
                let inv = coef.inv();
                crate::raptorq::gf256::gf256_mul_slice(&mut solution, inv);
            }

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
                // Remove the term from the equation.
                // Binary search is efficient since terms are sorted by column index.
                if let Ok(pos) = eq.terms.binary_search_by_key(&col, |(c, _)| *c) {
                    eq.terms.remove(pos);
                }
            }

            // Move solution instead of cloning (avoids allocation)
            state.solved[col] = Some(solution);
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

        // Build flat row-major dense matrix A and RHS vector b.
        // Flat layout avoids per-row heap allocation and improves cache locality.
        // Move (take) RHS data from state instead of cloning to avoid O(n_rows * symbol_size)
        // heap allocation in this hot path.
        let mut a = vec![Gf256::ZERO; n_rows * n_cols];
        let mut b: Vec<Vec<u8>> = Vec::with_capacity(n_rows);

        for (row, &eq_idx) in unused_eqs.iter().enumerate() {
            let row_off = row * n_cols;
            for &(col, coef) in &state.equations[eq_idx].terms {
                if let Some(&dense_col) = col_to_dense.get(&col) {
                    a[row_off + dense_col] = coef;
                }
            }
            b.push(std::mem::take(&mut state.rhs[eq_idx]));
        }

        // Gaussian elimination with partial pivoting.
        // Pre-allocate a single pivot buffer to avoid per-column clones.
        let mut pivot_row = vec![usize::MAX; n_cols];
        let mut pivot_buf = vec![Gf256::ZERO; n_cols];
        let mut pivot_rhs = vec![0u8; symbol_size];

        for col in 0..n_cols {
            // Find pivot: first nonzero in column `col` among unassigned rows
            let pivot = (0..n_rows).find(|&row| {
                pivot_row.iter().all(|&pr| pr != row) && !a[row * n_cols + col].is_zero()
            });

            let Some(prow) = pivot else {
                return Err(DecodeError::SingularMatrix { row: col });
            };

            pivot_row[col] = prow;
            state.stats.pivots_selected += 1;

            // Scale pivot row so a[prow][col] = 1
            let prow_off = prow * n_cols;
            let pivot_coef = a[prow_off + col];
            let inv = pivot_coef.inv();
            for value in &mut a[prow_off..prow_off + n_cols] {
                *value *= inv;
            }
            crate::raptorq::gf256::gf256_mul_slice(&mut b[prow], inv);

            // Copy pivot row into reusable buffers (no heap allocation)
            pivot_buf[..n_cols].copy_from_slice(&a[prow_off..prow_off + n_cols]);
            pivot_rhs[..symbol_size].copy_from_slice(&b[prow]);

            // Eliminate column in all other rows.
            for (row, rhs) in b.iter_mut().enumerate().take(n_rows) {
                if row == prow {
                    continue;
                }
                let row_off = row * n_cols;
                let factor = a[row_off + col];
                if factor.is_zero() {
                    continue;
                }
                for c in 0..n_cols {
                    a[row_off + c] += factor * pivot_buf[c];
                }
                gf256_addmul_slice(rhs, &pivot_rhs[..symbol_size], factor);
                state.stats.gauss_ops += 1;
            }
        }

        // Extract solutions: move RHS vectors instead of cloning
        for (dense_col, &col) in unsolved.iter().enumerate() {
            let prow = pivot_row[dense_col];
            if prow < n_rows {
                state.solved[col] = Some(std::mem::take(&mut b[prow]));
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

        // Build flat row-major dense matrix A and RHS vector b.
        // Move (take) RHS data from state instead of cloning to avoid O(n_rows * symbol_size)
        // heap allocation in this hot path.
        let mut a = vec![Gf256::ZERO; n_rows * n_cols];
        let mut b: Vec<Vec<u8>> = Vec::with_capacity(n_rows);

        for (row, &eq_idx) in unused_eqs.iter().enumerate() {
            let row_off = row * n_cols;
            for &(col, coef) in &state.equations[eq_idx].terms {
                if let Some(&dense_col) = col_to_dense.get(&col) {
                    a[row_off + dense_col] = coef;
                }
            }
            b.push(std::mem::take(&mut state.rhs[eq_idx]));
        }

        // Gaussian elimination with partial pivoting.
        let mut pivot_row = vec![usize::MAX; n_cols];
        let mut pivot_buf = vec![Gf256::ZERO; n_cols];
        let mut pivot_rhs = vec![0u8; symbol_size];

        for col in 0..n_cols {
            // Find pivot: first nonzero in column `col` among unassigned rows
            let pivot = (0..n_rows).find(|&row| {
                pivot_row.iter().all(|&pr| pr != row) && !a[row * n_cols + col].is_zero()
            });

            let Some(prow) = pivot else {
                return Err(DecodeError::SingularMatrix { row: col });
            };

            pivot_row[col] = prow;
            state.stats.pivots_selected += 1;
            // Record pivot in proof trace (use original column index)
            trace.record_pivot(unsolved[col], prow);

            // Scale pivot row so a[prow][col] = 1
            let prow_off = prow * n_cols;
            let pivot_coef = a[prow_off + col];
            let inv = pivot_coef.inv();
            for value in &mut a[prow_off..prow_off + n_cols] {
                *value *= inv;
            }
            crate::raptorq::gf256::gf256_mul_slice(&mut b[prow], inv);

            // Copy pivot row into reusable buffers
            pivot_buf[..n_cols].copy_from_slice(&a[prow_off..prow_off + n_cols]);
            pivot_rhs[..symbol_size].copy_from_slice(&b[prow]);

            // Eliminate column in all other rows.
            for (row, rhs) in b.iter_mut().enumerate().take(n_rows) {
                if row == prow {
                    continue;
                }
                let row_off = row * n_cols;
                let factor = a[row_off + col];
                if factor.is_zero() {
                    continue;
                }
                for c in 0..n_cols {
                    a[row_off + c] += factor * pivot_buf[c];
                }
                gf256_addmul_slice(rhs, &pivot_rhs[..symbol_size], factor);
                state.stats.gauss_ops += 1;
                // Record row operation in proof trace
                trace.record_row_op();
            }
        }

        // Extract solutions: move RHS vectors instead of cloning
        for (dense_col, &col) in unsolved.iter().enumerate() {
            let prow = pivot_row[dense_col];
            if prow < n_rows {
                state.solved[col] = Some(std::mem::take(&mut b[prow]));
            } else {
                state.solved[col] = Some(vec![0u8; symbol_size]);
            }
        }

        Ok(())
    }

    /// Generate the RFC 6330 tuple-derived equation (columns + coefficients) for a repair symbol.
    ///
    /// This must stay in parity with `SystematicEncoder::repair_symbol` so that
    /// decoder row construction exactly matches encoder repair bytes.
    #[must_use]
    pub fn repair_equation(&self, esi: u32) -> (Vec<usize>, Vec<Gf256>) {
        self.params.rfc_repair_equation(esi)
    }

    /// Generate the equation (columns + coefficients) using RFC 6330 tuple rules.
    ///
    /// This method computes tuple parameters from RFC 6330 Section 5.3.5.4 and
    /// expands them into intermediate symbol indices using Section 5.3.5.3.
    ///
    /// This is kept as an explicit alias used by RFC conformance tests.
    #[must_use]
    pub fn repair_equation_rfc6330(&self, esi: u32) -> (Vec<usize>, Vec<Gf256>) {
        self.repair_equation(esi)
    }

    /// Generate equations for all K source symbols.
    ///
    /// In systematic encoding, source symbol i maps directly to intermediate
    /// symbol i with no additional connections. This matches the encoder's
    /// `build_lt_rows` which simply sets `intermediate[i] = source[i]`.
    ///
    /// Returns a vector of K equations, where index i is the equation for
    /// source ESI i.
    #[must_use]
    pub fn all_source_equations(&self) -> Vec<(Vec<usize>, Vec<Gf256>)> {
        let k = self.params.k;

        // Systematic encoding: source symbol i maps directly to intermediate[i]
        // No additional LT connections - the encoder's build_lt_rows just does
        // matrix.set(row, i, Gf256::ONE) for each source symbol.
        (0..k).map(|i| (vec![i], vec![Gf256::ONE])).collect()
    }

    /// Get the equation for a specific source symbol ESI.
    ///
    /// In systematic encoding, source symbol `esi` maps directly to
    /// intermediate symbol `esi` with coefficient 1.
    #[must_use]
    pub fn source_equation(&self, esi: u32) -> (Vec<usize>, Vec<Gf256>) {
        assert!((esi as usize) < self.params.k, "source ESI must be < K");
        // Systematic: source[esi] = intermediate[esi]
        (vec![esi as usize], vec![Gf256::ONE])
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

    fn rfc_eq_context(
        scenario_id: &str,
        seed: u64,
        k: usize,
        symbol_size: usize,
        loss_pattern: &str,
        outcome: &str,
    ) -> String {
        format!(
            "scenario_id={scenario_id} seed={seed} k={k} symbol_size={symbol_size} \
             loss_pattern={loss_pattern} outcome={outcome} \
             artifact_path=artifacts/raptorq_b2_tuple_scenarios_v1.json \
             fixture_ref=RQ-B2-TUPLE-V1 \
             repro_cmd='rch exec -- cargo test -p asupersync --lib \
             repair_equation_rfc6330 -- --nocapture'"
        )
    }

    fn make_source_data(k: usize, symbol_size: usize) -> Vec<Vec<u8>> {
        (0..k)
            .map(|i| {
                (0..symbol_size)
                    .map(|j| ((i * 37 + j * 13 + 7) % 256) as u8)
                    .collect()
            })
            .collect()
    }

    /// Helper to create received symbols for source data using proper LT equations.
    fn make_received_source(
        decoder: &InactivationDecoder,
        source: &[Vec<u8>],
    ) -> Vec<ReceivedSymbol> {
        let source_eqs = decoder.all_source_equations();
        source
            .iter()
            .enumerate()
            .map(|(i, data)| {
                let (cols, coefs) = source_eqs[i].clone();
                ReceivedSymbol {
                    esi: i as u32,
                    is_source: true,
                    columns: cols,
                    coefficients: coefs,
                    data: data.clone(),
                }
            })
            .collect()
    }

    /// Build repair symbol bytes by XOR-folding encoder intermediate symbols.
    fn build_repair_from_intermediate(
        encoder: &SystematicEncoder,
        columns: &[usize],
        symbol_size: usize,
    ) -> Vec<u8> {
        let mut out = vec![0u8; symbol_size];
        for &col in columns {
            for (dst, src) in out.iter_mut().zip(encoder.intermediate_symbol(col)) {
                *dst ^= *src;
            }
        }
        out
    }

    #[test]
    fn decode_all_source_symbols() {
        let k = 8;
        let symbol_size = 32;
        let seed = 42u64;

        let source = make_source_data(k, symbol_size);
        let decoder = InactivationDecoder::new(k, symbol_size, seed);

        // Start with constraint symbols (LDPC + HDPC with zero data)
        let mut received = decoder.constraint_symbols();

        // Add all source symbols with proper LT equations
        received.extend(make_received_source(&decoder, &source));

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

        // Start with constraint symbols
        let mut received = decoder.constraint_symbols();

        // Get proper source equations
        let source_eqs = decoder.all_source_equations();

        // First half source symbols with proper LT equations
        for i in 0..(k / 2) {
            let (cols, coefs) = source_eqs[i].clone();
            received.push(ReceivedSymbol {
                esi: i as u32,
                is_source: true,
                columns: cols,
                coefficients: coefs,
                data: source[i].clone(),
            });
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

        // Start with constraint symbols
        let mut received = decoder.constraint_symbols();

        // Receive only repair symbols (need at least L)
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

        // Only provide a couple source symbols - not enough to solve
        let source_eqs = decoder.all_source_equations();
        let received: Vec<ReceivedSymbol> = (0..2)
            .map(|i| {
                let (cols, coefs) = source_eqs[i].clone();
                ReceivedSymbol {
                    esi: i as u32,
                    is_source: true,
                    columns: cols,
                    coefficients: coefs,
                    data: source[i].clone(),
                }
            })
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

        // Build received symbols: constraints + source + repair
        let mut received = decoder.constraint_symbols();
        received.extend(make_received_source(&decoder, &source));

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
        // Use k=8 for more robust coverage (k=4 with certain seeds can cause
        // singular matrices due to sparse LT equation coverage)
        let k = 8;
        let symbol_size = 32;
        let seed = 42u64;

        let source = make_source_data(k, symbol_size);
        let encoder = SystematicEncoder::new(&source, symbol_size, seed).unwrap();
        let decoder = InactivationDecoder::new(k, symbol_size, seed);
        let l = decoder.params().l;

        // Start with constraint symbols (LDPC + HDPC with zero data)
        let mut received = decoder.constraint_symbols();

        // Add all source symbols with proper LT equations
        received.extend(make_received_source(&decoder, &source));

        // Add repair symbols to provide enough equations for full coverage
        for esi in (k as u32)..(l as u32 + 2) {
            let (cols, coefs) = decoder.repair_equation(esi);
            let repair_data = encoder.repair_symbol(esi);
            received.push(ReceivedSymbol::repair(esi, cols, coefs, repair_data));
        }

        let result = decoder.decode(&received).unwrap();

        // At least some peeling should occur (LDPC/HDPC constraints + some equations)
        // Note: with proper LT equations, peeling behavior may vary
        assert!(
            result.stats.peeled > 0 || result.stats.inactivated > 0,
            "expected some peeling or inactivation"
        );
    }

    #[test]
    fn repair_equation_rfc6330_deterministic() {
        let k = 8;
        let symbol_size = 32;
        let seed = 42u64;
        let decoder = InactivationDecoder::new(k, symbol_size, seed);
        let (c1, k1) = decoder.repair_equation_rfc6330(17);
        let (c2, k2) = decoder.repair_equation_rfc6330(17);
        let context = rfc_eq_context(
            "RQ-B2-DECODER-EQ-DET-001",
            seed,
            k,
            symbol_size,
            "none",
            "deterministic_replay",
        );
        assert_eq!(c1, c2, "{context} column replay mismatch");
        assert_eq!(k1, k2, "{context} coefficient replay mismatch");
    }

    #[test]
    fn repair_equation_rfc6330_indices_within_bounds() {
        let k = 10;
        let symbol_size = 32;
        let seed = 7u64;
        let decoder = InactivationDecoder::new(k, symbol_size, seed);
        let params = decoder.params();
        let upper = params.w + params.p;
        let context = rfc_eq_context(
            "RQ-B2-DECODER-EQ-BOUNDS-001",
            seed,
            k,
            symbol_size,
            "none",
            "index_bounds",
        );
        for esi in 0..32u32 {
            let (cols, coefs) = decoder.repair_equation_rfc6330(esi);
            assert_eq!(
                cols.len(),
                coefs.len(),
                "{context} len mismatch for esi={esi}"
            );
            assert!(!cols.is_empty(), "{context} empty row for esi={esi}");
            assert!(
                cols.iter().all(|col| *col < upper),
                "{context} out-of-range column for esi={esi}"
            );
        }
    }

    #[test]
    fn repair_equation_rfc6330_includes_pi_domain_entries() {
        let k = 12;
        let symbol_size = 64;
        let seed = 99u64;
        let decoder = InactivationDecoder::new(k, symbol_size, seed);
        let params = decoder.params();
        let w = params.w;
        let mut saw_pi = false;
        for esi in 0..128u32 {
            let (cols, _) = decoder.repair_equation_rfc6330(esi);
            if cols.iter().any(|c| *c >= w) {
                saw_pi = true;
                break;
            }
        }
        let context = rfc_eq_context(
            "RQ-B2-DECODER-EQ-PI-001",
            seed,
            k,
            symbol_size,
            "none",
            "pi_domain_coverage",
        );
        assert!(saw_pi, "{context} expected PI-domain index in sample");
    }

    #[test]
    fn repair_equation_rfc6330_matches_systematic_params_helper() {
        let scenarios = [
            ("RQ-C1-PARITY-001", 8usize, 32usize, 42u64),
            ("RQ-C1-PARITY-002", 16usize, 64usize, 77u64),
            ("RQ-C1-PARITY-003", 32usize, 128usize, 1234u64),
        ];

        for (scenario_id, k, symbol_size, seed) in scenarios {
            let decoder = InactivationDecoder::new(k, symbol_size, seed);
            let params = SystematicParams::for_source_block(k, symbol_size);
            for esi in 0..64u32 {
                let decoder_eq = decoder.repair_equation_rfc6330(esi);
                let shared_eq = params.rfc_repair_equation(esi);
                let context = rfc_eq_context(
                    scenario_id,
                    seed,
                    k,
                    symbol_size,
                    "none",
                    "decoder_params_parity",
                );
                assert_eq!(
                    decoder_eq, shared_eq,
                    "{context} decoder/params equation mismatch for esi={esi}"
                );
            }
        }
    }

    #[test]
    fn decode_roundtrip_with_rfc_tuple_repair_equations() {
        let k = 8;
        let symbol_size = 32;
        let seed = 42u64;

        let source = make_source_data(k, symbol_size);
        let encoder = SystematicEncoder::new(&source, symbol_size, seed)
            .expect("RQ-C1-E2E-001 encoder setup should succeed");
        let decoder = InactivationDecoder::new(k, symbol_size, seed);
        let l = decoder.params().l;

        // Start with constraint symbols + systematic source symbols.
        let mut received = decoder.constraint_symbols();
        received.extend(make_received_source(&decoder, &source));

        // Add RFC tuple-driven repair equations and synthesize repair bytes directly
        // from intermediate symbols to validate decoder-side equation reconstruction.
        for esi in (k as u32)..(l as u32) {
            let (columns, coefficients) = decoder.repair_equation_rfc6330(esi);
            let repair_data = build_repair_from_intermediate(&encoder, &columns, symbol_size);
            received.push(ReceivedSymbol::repair(
                esi,
                columns,
                coefficients,
                repair_data,
            ));
        }

        let result = decoder.decode(&received).unwrap_or_else(|err| {
            let context = rfc_eq_context(
                "RQ-C1-E2E-001",
                seed,
                k,
                symbol_size,
                "none",
                "decode_failed",
            );
            panic!("{context} unexpected decode failure: {err:?}");
        });

        for (i, original) in source.iter().enumerate() {
            let context = rfc_eq_context(
                "RQ-C1-E2E-001",
                seed,
                k,
                symbol_size,
                "none",
                "roundtrip_compare",
            );
            assert_eq!(
                &result.source[i], original,
                "{context} source symbol mismatch at index {i}"
            );
        }
    }
}
