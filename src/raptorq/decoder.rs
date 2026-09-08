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

use crate::raptorq::gf256::{Gf256, gf256_addmul_slice};
use crate::raptorq::linalg::{GaussianRankProfile, coefficient_rank_profile};
use crate::raptorq::proof::{
    DecodeConfig, DecodeProof, EliminationTrace, FailureReason, InactivationStrategy, PeelingTrace,
    ReceivedSummary,
};
use crate::raptorq::rfc6330::repair_indices_for_esi;
use crate::raptorq::systematic::{ConstraintMatrix, SystematicError, SystematicParams};
use crate::raptorq::{decision_contract, decision_contract::GovernanceSnapshot};
use crate::types::ObjectId;

use std::collections::{HashMap, VecDeque};
use std::hash::{Hash, Hasher};
use std::sync::Arc;
use std::time::{Duration, Instant};

// ============================================================================
// Column state tracking
// ============================================================================

/// Dense column state for O(1) membership and transitions.
/// Replaces BTreeSet<usize> lookups with direct array indexing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
enum ColumnState {
    /// Column is active (unsolved, not inactivated).
    #[default]
    Active,
    /// Column has been solved during peeling phase.
    Solved,
    /// Column has been inactivated (deferred to Gaussian elimination).
    Inactive,
}

// ============================================================================
// Rate limiting and budget tracking
// ============================================================================

/// Maximum ESI value allowed to prevent amplification attacks.
/// ESI values near u32::MAX can cause expensive operations.
const MAX_ALLOWED_ESI: u32 = 1_000_000;

/// Maximum columns generated per ESI to prevent matrix blow-up.
const MAX_COLUMNS_PER_ESI: usize = 1000;

/// Minimum compute budget (in arbitrary units) for dense matrix operations.
const MIN_DENSE_COMPUTE_BUDGET: u64 = 1_000_000;

/// RFC 6330 tuples expand to at most 30 LT columns plus 2 PI columns.
const MAX_RFC6330_COLUMNS_PER_ESI: u64 = 32;

/// Rate limiting entry for ESI/ObjectId combinations.
#[derive(Debug, Clone)]
struct EsiRateLimit {
    /// Last access time for this ESI/ObjectId.
    last_access: Instant,
    /// Number of accesses in current time window.
    access_count: u32,
    /// Compute budget consumed by this ESI.
    compute_budget_used: u64,
}

impl Default for EsiRateLimit {
    fn default() -> Self {
        Self {
            last_access: Instant::now(),
            access_count: 0,
            compute_budget_used: 0,
        }
    }
}

/// Compute budget tracker for expensive matrix operations.
#[derive(Debug, Default)]
struct ComputeBudget {
    /// Current budget consumed.
    used: u64,
    /// Maximum budget allowed.
    max: u64,
}

impl ComputeBudget {
    /// Create new budget with maximum limit.
    fn new(max: u64) -> Self {
        Self { used: 0, max }
    }

    /// Check if operation would exceed budget.
    fn would_exceed(&self, cost: u64) -> bool {
        self.used.saturating_add(cost) > self.max
    }

    /// Consume budget for operation, returning error if exceeded.
    fn consume(&mut self, cost: u64) -> Result<(), DecodeError> {
        if self.would_exceed(cost) {
            return Err(DecodeError::ComputeBudgetExhausted {
                used: self.used,
                requested: cost,
                max: self.max,
            });
        }
        self.used = self.used.saturating_add(cost);
        Ok(())
    }
}

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
    /// Column indices that this symbol depends on (intermediate symbol indices 0..L-1).
    /// For source symbols, this should be empty; the decoder derives the canonical
    /// RFC tuple equation from `esi`. Only repair symbols provide explicit columns.
    pub columns: Vec<usize>,
    /// GF(256) coefficients for each column (same length as `columns`).
    /// For XOR-based LT, all coefficients are 1.
    pub coefficients: Vec<Gf256>,
    /// The symbol data.
    pub data: Vec<u8>,
}

type SeenEquationPayload<'a> = (&'a [usize], &'a [Gf256], &'a [u8]);
type SeenEquationPayloads<'a> = HashMap<u32, Vec<SeenEquationPayload<'a>>>;

/// Reason for decode failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecodeError {
    /// Not enough symbols received to solve the system.
    InsufficientSymbols {
        /// Number of symbols received.
        received: usize,
        /// Minimum caller-supplied equations required before decoding can proceed.
        required: usize,
    },
    /// Matrix became singular during Gaussian elimination.
    SingularMatrix {
        /// Deterministic witness row for elimination failure.
        ///
        /// This may be either:
        /// - the original unsolved column id where no pivot was found, or
        /// - an equation row index that reduced to `0 = b` (inconsistent system).
        row: usize,
    },
    /// Symbol size mismatch.
    SymbolSizeMismatch {
        /// Expected size.
        expected: usize,
        /// Actual size found.
        actual: usize,
    },
    /// Received symbol has mismatched equation vectors.
    SymbolEquationArityMismatch {
        /// ESI of the malformed symbol.
        esi: u32,
        /// Number of column indices provided.
        columns: usize,
        /// Number of coefficients provided.
        coefficients: usize,
    },
    /// Received symbol references a column outside the decode domain [0, L).
    ColumnIndexOutOfRange {
        /// ESI of the malformed symbol.
        esi: u32,
        /// Offending column index.
        column: usize,
        /// Exclusive upper bound for valid columns.
        max_valid: usize,
    },
    /// A source symbol used an ESI outside the systematic source domain [0, K).
    SourceEsiOutOfRange {
        /// ESI of the malformed source symbol.
        esi: u32,
        /// Exclusive upper bound for valid source ESIs.
        max_valid: usize,
    },
    /// A source symbol did not use the required identity equation `C[esi] = data`.
    InvalidSourceSymbolEquation {
        /// ESI of the malformed source symbol.
        esi: u32,
        /// Required intermediate column for that source symbol.
        expected_column: usize,
    },
    /// Internal corruption guard: reconstructed output does not satisfy an
    /// input equation and is therefore unsafe to return as success.
    CorruptDecodedOutput {
        /// ESI of the mismatched equation row.
        esi: u32,
        /// First byte index where mismatch was detected.
        byte_index: usize,
        /// Reconstructed byte from decoded intermediate symbols.
        expected: u8,
        /// Received RHS byte from the input symbol.
        actual: u8,
    },
    /// Compute budget exhausted during dense matrix operations.
    ///
    /// br-asupersync-ju2k01: Prevents RaptorQ decoder amplification DoS
    /// attacks via malicious ESI values that force expensive O(L³) operations.
    ComputeBudgetExhausted {
        /// Budget already consumed.
        used: u64,
        /// Additional budget requested by operation.
        requested: u64,
        /// Maximum budget allowed.
        max: u64,
    },
    /// ESI rate limit exceeded for this ObjectId.
    ///
    /// br-asupersync-ju2k01: Prevents amplification attacks where malicious
    /// ESI values near u32::MAX cause excessive column generation.
    EsiRateLimitExceeded {
        /// The ESI that exceeded limits.
        esi: u32,
        /// Number of columns that would be generated.
        column_count: usize,
        /// Maximum allowed columns per ESI.
        max_columns: usize,
    },
}

/// Decode failure classification used to separate retryable failures from
/// malformed/corruption failures at the API boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecodeFailureClass {
    /// Retry may succeed with additional symbols/redundancy.
    Recoverable,
    /// Input is malformed or decode invariants were violated.
    Unrecoverable,
}

impl DecodeError {
    /// Classify this decode failure as recoverable or unrecoverable.
    #[must_use]
    #[inline]
    pub const fn failure_class(&self) -> DecodeFailureClass {
        match self {
            Self::InsufficientSymbols { .. } | Self::SingularMatrix { .. } => {
                DecodeFailureClass::Recoverable
            }
            Self::SymbolSizeMismatch { .. }
            | Self::SymbolEquationArityMismatch { .. }
            | Self::ColumnIndexOutOfRange { .. }
            | Self::SourceEsiOutOfRange { .. }
            | Self::InvalidSourceSymbolEquation { .. }
            | Self::CorruptDecodedOutput { .. }
            | Self::ComputeBudgetExhausted { .. }
            | Self::EsiRateLimitExceeded { .. } => DecodeFailureClass::Unrecoverable,
        }
    }

    /// True when this failure can be retried by supplying additional symbols.
    #[must_use]
    #[inline]
    pub const fn is_recoverable(&self) -> bool {
        matches!(self.failure_class(), DecodeFailureClass::Recoverable)
    }

    /// True when this failure indicates malformed input or corruption.
    #[must_use]
    #[inline]
    pub const fn is_unrecoverable(&self) -> bool {
        matches!(self.failure_class(), DecodeFailureClass::Unrecoverable)
    }
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
    /// True when the decoder entered hard-regime inactivation mode.
    ///
    /// Hard regime is a deterministic fallback for dense/near-square decode
    /// systems where naive pivoting is more likely to encounter fragile paths.
    pub hard_regime_activated: bool,
    /// Number of pivots selected by the hard-regime Markowitz-style strategy.
    pub markowitz_pivots: usize,
    /// Number of times baseline elimination deterministically retried in hard regime.
    pub hard_regime_fallbacks: usize,
    /// Hard-regime branch selected for dense elimination.
    pub hard_regime_branch: Option<&'static str>,
    /// Deterministic reason an accelerated hard-regime branch fell back to conservative mode.
    pub hard_regime_conservative_fallback_reason: Option<&'static str>,
    /// Number of equation indices pushed into the deterministic peel queue.
    pub peel_queue_pushes: usize,
    /// Number of equation indices popped from the deterministic peel queue.
    pub peel_queue_pops: usize,
    /// Maximum queue depth observed during peeling.
    pub peel_frontier_peak: usize,
    /// Number of rows in the extracted dense core presented to elimination.
    pub dense_core_rows: usize,
    /// Number of columns in the extracted dense core presented to elimination.
    pub dense_core_cols: usize,
    /// Number of zero-information rows dropped while extracting the dense core.
    pub dense_core_dropped_rows: usize,
    /// Deterministic reason we fell back from peeling into dense elimination.
    pub peeling_fallback_reason: Option<&'static str>,
    /// Runtime policy mode selected for dense elimination planning.
    pub policy_mode: Option<&'static str>,
    /// Deterministic reason string for the runtime policy decision.
    pub policy_reason: Option<&'static str>,
    /// Replay pointer for policy-decision forensics.
    pub policy_replay_ref: Option<&'static str>,
    /// Concrete G7 governance output for this decoder policy decision.
    pub governance: Option<decision_contract::GovernanceTelemetry>,
    /// Policy feature: matrix density in permille.
    pub policy_density_permille: usize,
    /// Policy feature: estimated rank deficit pressure in permille.
    pub policy_rank_deficit_permille: usize,
    /// Policy feature: inactivation pressure in permille.
    pub policy_inactivation_pressure_permille: usize,
    /// Policy feature: row/column overhead ratio in permille.
    pub policy_overhead_ratio_permille: usize,
    /// True if policy feature extraction exhausted its strict budget.
    pub policy_budget_exhausted: bool,
    /// Expected-loss term for conservative baseline mode.
    pub policy_baseline_loss: u32,
    /// Expected-loss term for high-support mode.
    pub policy_high_support_loss: u32,
    /// Expected-loss term for block-schur mode.
    pub policy_block_schur_loss: u32,
    /// Number of dense-factor cache hits during this decode.
    pub factor_cache_hits: usize,
    /// Number of dense-factor cache misses during this decode.
    pub factor_cache_misses: usize,
    /// Number of dense-factor cache insertions during this decode.
    pub factor_cache_inserts: usize,
    /// Number of dense-factor cache evictions during this decode.
    pub factor_cache_evictions: usize,
    /// Number of fingerprint collisions observed while probing cache keys.
    pub factor_cache_lookup_collisions: usize,
    /// Last dense-factor cache key fingerprint consulted by the decoder.
    pub factor_cache_last_key: Option<u64>,
    /// Deterministic reason for the most recent dense-factor cache decision.
    pub factor_cache_last_reason: Option<&'static str>,
    /// Whether the most recent cache probe was eligible for artifact reuse.
    pub factor_cache_last_reuse_eligible: Option<bool>,
    /// Number of entries resident in the dense-factor cache after the last operation.
    pub factor_cache_entries: usize,
    /// Bounded capacity used by the dense-factor cache policy.
    pub factor_cache_capacity: usize,
    /// True when the wavefront decode pipeline was used.
    pub wavefront_active: bool,
    /// Number of bounded assembly+peel batches processed by the wavefront pipeline.
    pub wavefront_batches: usize,
    /// Number of symbols peeled during assembly batches (overlap region).
    pub wavefront_overlap_peeled: usize,
    /// Wavefront batch size used for assembly+peel fusion.
    pub wavefront_batch_size: usize,
}

/// Result of successful decoding.
#[derive(Debug)]
pub struct DecodeResult {
    /// Recovered intermediate symbols (L symbols).
    pub intermediate: Vec<Vec<u8>>,
    /// Recovered source symbols reconstructed from the RFC source equations.
    pub source: Vec<Vec<u8>>,
    /// Decode statistics.
    pub stats: DecodeStats,
}

/// Linear-rank summary for a received block equation set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RankStatus {
    /// Independent equation rows in the full decoder system.
    pub rank: usize,
    /// Intermediate-symbol columns that must be solved.
    pub columns: usize,
    /// Additional independent equations required for full rank.
    pub deficit: usize,
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
    /// Dense per-column state for O(1) membership tests and transitions.
    /// Replaces BTreeSet<usize> active_cols and inactive_cols with direct indexing.
    column_states: Vec<ColumnState>,
    /// Statistics.
    stats: DecodeStats,
}

const DENSE_FACTOR_CACHE_CAPACITY: usize = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DenseFactorCacheResult {
    Hit,
    MissInserted,
    MissEvicted,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum DenseFactorCacheLookup {
    Hit(Arc<DenseFactorArtifact>),
    MissNoEntry,
    MissFingerprintCollision,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DenseFactorArtifact {
    dense_cols: Vec<usize>,
    col_to_dense: DenseColIndexMap,
}

impl DenseFactorArtifact {
    fn new(dense_cols: Vec<usize>) -> Self {
        let col_to_dense = build_dense_col_index_map(&dense_cols);
        Self {
            dense_cols,
            col_to_dense,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum DenseColIndexMap {
    Direct(Vec<usize>),
    SortedPairs(Vec<(usize, usize)>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DenseFactorSignature {
    fingerprint: u64,
    unsolved: Vec<usize>,
    row_offsets: Vec<usize>,
    row_terms_flat: Vec<(usize, u8)>,
}

impl DenseFactorSignature {
    fn from_equations(equations: &[Equation], dense_rows: &[usize], unsolved: &[usize]) -> Self {
        let mut row_offsets = Vec::with_capacity(dense_rows.len());
        // Upper bound avoids growth reallocations in bursty decode signatures.
        let row_terms_capacity = dense_rows
            .iter()
            .map(|&eq_idx| equations[eq_idx].terms.len())
            .sum();
        let mut row_terms_flat = Vec::with_capacity(row_terms_capacity);
        for &eq_idx in dense_rows {
            let mut unsolved_cursor = 0usize;
            for &(col, coef) in &equations[eq_idx].terms {
                if coef.is_zero() {
                    continue;
                }
                while unsolved_cursor < unsolved.len() && unsolved[unsolved_cursor] < col {
                    unsolved_cursor = unsolved_cursor.saturating_add(1);
                }
                if unsolved_cursor >= unsolved.len() {
                    break;
                }
                if unsolved[unsolved_cursor] == col {
                    row_terms_flat.push((col, coef.raw()));
                }
            }
            row_offsets.push(row_terms_flat.len());
        }

        let mut hasher = crate::util::DetHasher::default();
        unsolved.hash(&mut hasher);
        row_offsets.hash(&mut hasher);
        row_terms_flat.hash(&mut hasher);
        let fingerprint = hasher.finish();

        Self {
            fingerprint,
            unsolved: unsolved.to_vec(),
            row_offsets,
            row_terms_flat,
        }
    }
}

#[derive(Debug, Clone)]
struct DenseFactorCacheEntry {
    signature: DenseFactorSignature,
    artifact: Arc<DenseFactorArtifact>,
}

#[derive(Debug, Default)]
struct DenseFactorCache {
    entries: VecDeque<DenseFactorCacheEntry>,
}

impl DenseFactorCache {
    fn lookup(&self, signature: &DenseFactorSignature) -> DenseFactorCacheLookup {
        let mut saw_fingerprint_collision = false;
        for entry in &self.entries {
            if entry.signature.fingerprint != signature.fingerprint {
                continue;
            }
            if entry.signature == *signature {
                return DenseFactorCacheLookup::Hit(entry.artifact.clone());
            }
            saw_fingerprint_collision = true;
        }

        if saw_fingerprint_collision {
            DenseFactorCacheLookup::MissFingerprintCollision
        } else {
            DenseFactorCacheLookup::MissNoEntry
        }
    }

    fn insert(
        &mut self,
        signature: DenseFactorSignature,
        artifact: Arc<DenseFactorArtifact>,
    ) -> DenseFactorCacheResult {
        if let Some(existing) = self
            .entries
            .iter_mut()
            .find(|entry| entry.signature == signature)
        {
            existing.artifact = artifact;
            return DenseFactorCacheResult::MissInserted;
        }

        let result = if self.entries.len() >= DENSE_FACTOR_CACHE_CAPACITY {
            let _ = self.entries.pop_front();
            DenseFactorCacheResult::MissEvicted
        } else {
            DenseFactorCacheResult::MissInserted
        };
        self.entries.push_back(DenseFactorCacheEntry {
            signature,
            artifact,
        });
        result
    }

    #[inline]
    fn len(&self) -> usize {
        self.entries.len()
    }
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
        let canonical = columns
            .iter()
            .zip(coefficients.iter())
            .scan(None, |prev, (&col, &coef)| {
                let ordered = prev.is_none_or(|last| last < col);
                *prev = Some(col);
                Some(ordered && !coef.is_zero())
            })
            .all(|term_ok| term_ok);

        if canonical {
            return Self {
                terms: columns.into_iter().zip(coefficients).collect(),
                used: false,
            };
        }

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
    #[inline]
    fn degree(&self) -> usize {
        self.terms.len()
    }

    /// Remove and return the coefficient for the given column, if present.
    #[inline]
    fn take_coef(&mut self, col: usize) -> Option<Gf256> {
        let idx = self.terms.binary_search_by_key(&col, |(c, _)| *c).ok()?;
        Some(self.terms.remove(idx).1)
    }

    /// Optimized removal for degree-2 equations that avoids binary search.
    /// Returns (coefficient, remaining_column) if the column was found and removed
    /// from a degree-2 equation, None otherwise.
    #[inline]
    fn take_coef_degree2_fast(&mut self, col: usize) -> Option<(Gf256, usize)> {
        if self.terms.len() != 2 {
            return None;
        }
        if self.terms[0].0 == col {
            let coef = self.terms[0].1;
            let remaining = self.terms[1].0;
            // Remove the first element by moving the second to first position
            self.terms[0] = self.terms[1];
            self.terms.truncate(1);
            Some((coef, remaining))
        } else if self.terms[1].0 == col {
            let coef = self.terms[1].1;
            let remaining = self.terms[0].0;
            // Remove the second element by truncating
            self.terms.truncate(1);
            Some((coef, remaining))
        } else {
            None
        }
    }

    #[inline]
    fn extract_solved_terms(
        &mut self,
        solved: &[Option<Vec<u8>>],
        removed: &mut Vec<(usize, Gf256)>,
    ) {
        removed.clear();

        let mut write = 0usize;
        for read in 0..self.terms.len() {
            let term = self.terms[read];
            if !term.1.is_zero() && solved[term.0].is_some() {
                removed.push(term);
            } else {
                if write != read {
                    self.terms[write] = term;
                }
                write += 1;
            }
        }

        self.terms.truncate(write);
    }
}

#[inline]
fn original_col_for_dense(unsolved: &[usize], dense_col: usize) -> usize {
    unsolved.get(dense_col).copied().unwrap_or(dense_col)
}

#[inline]
fn singular_matrix_error(unsolved: &[usize], dense_col: usize) -> DecodeError {
    DecodeError::SingularMatrix {
        row: original_col_for_dense(unsolved, dense_col),
    }
}

#[inline]
fn inconsistent_matrix_error(unused_eqs: &[usize], dense_row: usize) -> DecodeError {
    DecodeError::SingularMatrix {
        row: unused_eqs.get(dense_row).copied().unwrap_or(dense_row),
    }
}

fn first_inconsistent_dense_row(
    a: &[Gf256],
    n_rows: usize,
    n_cols: usize,
    b: &[Vec<u8>],
) -> Option<usize> {
    (0..n_rows).find(|&row| {
        let row_off = row * n_cols;
        a[row_off..row_off.saturating_add(n_cols)]
            .iter()
            .all(|coef| coef.is_zero())
            && b[row].iter().any(|&byte| byte != 0)
    })
}

#[inline]
fn active_degree_one_col(state: &DecoderState, eq: &Equation) -> Option<usize> {
    if eq.used || eq.degree() != 1 {
        return None;
    }
    let col = eq.terms[0].0;
    if state.column_states[col] == ColumnState::Active && state.solved[col].is_none() {
        Some(col)
    } else {
        None
    }
}

fn build_dense_core_rows(
    state: &DecoderState,
    unused_eqs: &[usize],
    unsolved: &[usize],
) -> Result<(Vec<usize>, usize), DecodeError> {
    let mut unsolved_mask = vec![false; state.params.l];
    for &col in unsolved {
        unsolved_mask[col] = true;
    }

    let mut dense_rows = Vec::with_capacity(unused_eqs.len());
    let mut dropped_zero_rows = 0usize;

    for &eq_idx in unused_eqs {
        let has_unsolved_term = state.equations[eq_idx]
            .terms
            .iter()
            .any(|(col, coef)| unsolved_mask[*col] && !coef.is_zero());
        if has_unsolved_term {
            dense_rows.push(eq_idx);
            continue;
        }

        if state.rhs[eq_idx].iter().any(|&byte| byte != 0) {
            return Err(DecodeError::SingularMatrix { row: eq_idx });
        }
        dropped_zero_rows += 1;
    }

    Ok((dense_rows, dropped_zero_rows))
}

fn validate_dense_core_rhs_widths(
    state: &DecoderState,
    dense_rows: &[usize],
    symbol_size: usize,
) -> Result<(), DecodeError> {
    for &eq_idx in dense_rows {
        let actual = state.rhs[eq_idx].len();
        if actual != symbol_size {
            return Err(DecodeError::SymbolSizeMismatch {
                expected: symbol_size,
                actual,
            });
        }
    }
    Ok(())
}

const DENSE_COL_ABSENT: usize = usize::MAX;
const DENSE_COL_DIRECT_MAP_RANGE_RATIO: usize = 8;

#[inline]
fn build_dense_col_index_map(unsolved: &[usize]) -> DenseColIndexMap {
    let Some(max_col) = unsolved.iter().copied().max() else {
        return DenseColIndexMap::Direct(Vec::new());
    };

    let direct_map_max_col = unsolved
        .len()
        .saturating_mul(DENSE_COL_DIRECT_MAP_RANGE_RATIO);
    if max_col <= direct_map_max_col {
        let mut col_to_dense = vec![DENSE_COL_ABSENT; max_col.saturating_add(1)];
        for (dense_col, &col) in unsolved.iter().enumerate() {
            col_to_dense[col] = dense_col;
        }
        DenseColIndexMap::Direct(col_to_dense)
    } else {
        let mut pairs: Vec<(usize, usize)> = unsolved
            .iter()
            .copied()
            .enumerate()
            .map(|(dense_col, col)| (col, dense_col))
            .collect();
        pairs.sort_by_key(|(col, _)| *col);
        DenseColIndexMap::SortedPairs(pairs)
    }
}

#[inline]
fn dense_col_index_from_direct(map: &[usize], col: usize) -> Option<usize> {
    let dense_col = *map.get(col)?;
    if dense_col == DENSE_COL_ABSENT {
        return None;
    }
    Some(dense_col)
}

#[inline]
fn dense_col_index_from_sorted_pairs(pairs: &[(usize, usize)], col: usize) -> Option<usize> {
    let idx = pairs
        .binary_search_by_key(&col, |(candidate_col, _)| *candidate_col)
        .ok()?;
    Some(pairs[idx].1)
}

#[inline]
fn dense_col_index(col_to_dense: &DenseColIndexMap, col: usize) -> Option<usize> {
    match col_to_dense {
        DenseColIndexMap::Direct(map) => dense_col_index_from_direct(map, col),
        DenseColIndexMap::SortedPairs(pairs) => dense_col_index_from_sorted_pairs(pairs, col),
    }
}

fn sparse_first_dense_columns(
    equations: &[Equation],
    dense_rows: &[usize],
    unsolved: &[usize],
) -> Vec<usize> {
    if unsolved.len() < 2 {
        return unsolved.to_vec();
    }

    let mut support = vec![0usize; unsolved.len()];

    // Hot-path optimization: runtime unsolved columns are deterministically
    // sorted; use a two-pointer scan to avoid allocating an index map.
    if unsolved.windows(2).all(|w| w[0] <= w[1]) {
        for &eq_idx in dense_rows {
            let mut unsolved_cursor = 0usize;
            for &(col, coef) in &equations[eq_idx].terms {
                if coef.is_zero() {
                    continue;
                }
                while unsolved_cursor < unsolved.len() && unsolved[unsolved_cursor] < col {
                    unsolved_cursor = unsolved_cursor.saturating_add(1);
                }
                if unsolved_cursor >= unsolved.len() {
                    break;
                }
                if unsolved[unsolved_cursor] == col {
                    support[unsolved_cursor] += 1;
                }
            }
        }
    } else {
        // Compatibility fallback for non-canonical caller input.
        let col_to_dense = build_dense_col_index_map(unsolved);
        for &eq_idx in dense_rows {
            for &(col, coef) in &equations[eq_idx].terms {
                if coef.is_zero() {
                    continue;
                }
                if let Some(dense_col) = dense_col_index(&col_to_dense, col) {
                    support[dense_col] += 1;
                }
            }
        }
    }

    let mut ordered: Vec<(usize, usize)> = unsolved
        .iter()
        .copied()
        .enumerate()
        .map(|(dense_col, col)| (col, support[dense_col]))
        .collect();

    // Sparse-first ordering shrinks expected fill-in while remaining deterministic.
    ordered.sort_by(|(col_a, support_a), (col_b, support_b)| {
        support_a.cmp(support_b).then_with(|| col_a.cmp(col_b))
    });
    ordered.into_iter().map(|(col, _)| col).collect()
}

fn failure_reason_with_trace(err: &DecodeError, elimination: &EliminationTrace) -> FailureReason {
    match err {
        DecodeError::SingularMatrix { row } => FailureReason::SingularMatrix {
            row: *row,
            attempted_cols: elimination.pivot_events.iter().map(|ev| ev.col).collect(),
        },
        _ => FailureReason::from(err),
    }
}

const HARD_REGIME_MIN_COLS: usize = 8;
const HARD_REGIME_DENSITY_PERCENT: usize = 35;
const HARD_REGIME_NEAR_SQUARE_EXTRA_ROWS: usize = 2;
const BLOCK_SCHUR_MIN_COLS: usize = 12;
const BLOCK_SCHUR_MIN_DENSITY_PERCENT: usize = 45;
const BLOCK_SCHUR_TRAILING_COLS: usize = 4;
const HYBRID_SPARSE_COST_NUMERATOR: usize = 3;
const HYBRID_SPARSE_COST_DENOMINATOR: usize = 5;
const SMALL_ROW_DENSE_FASTPATH_COLS: usize = 4;
const POLICY_FEATURE_BUDGET_CELLS: usize = 4096;
const POLICY_REPLAY_REF: &str = "replay:rq-track-f-runtime-policy-v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct DecoderPolicyFeatures {
    density_permille: usize,
    rank_deficit_permille: usize,
    inactivation_pressure_permille: usize,
    overhead_ratio_permille: usize,
    budget_exhausted: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DecoderPolicyMode {
    ConservativeBaseline,
    HighSupportFirst,
    BlockSchurLowRank,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct DecoderPolicyDecision {
    mode: DecoderPolicyMode,
    features: DecoderPolicyFeatures,
    baseline_loss: u32,
    high_support_loss: u32,
    block_schur_loss: u32,
    reason: &'static str,
    governance: Option<decision_contract::GovernanceTelemetry>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HardRegimePlan {
    Markowitz,
    BlockSchurLowRank { split_col: usize },
}

impl HardRegimePlan {
    const fn label(self) -> &'static str {
        match self {
            Self::Markowitz => "markowitz",
            Self::BlockSchurLowRank { .. } => "block_schur_low_rank",
        }
    }

    const fn strategy(self) -> InactivationStrategy {
        match self {
            Self::Markowitz => InactivationStrategy::HighSupportFirst,
            Self::BlockSchurLowRank { .. } => InactivationStrategy::BlockSchurLowRank,
        }
    }
}

fn matrix_nonzero_count(a: &[Gf256]) -> usize {
    a.iter().filter(|coef| !coef.is_zero()).count()
}

fn clamp_usize_to_u32(value: usize) -> u32 {
    u32::try_from(value).unwrap_or(u32::MAX)
}

fn compute_decoder_policy_features(
    n_rows: usize,
    n_cols: usize,
    dense_nonzeros: usize,
    unsupported_cols: usize,
    inactivation_pressure_permille: usize,
) -> DecoderPolicyFeatures {
    if n_rows == 0 || n_cols == 0 {
        return DecoderPolicyFeatures {
            density_permille: 0,
            rank_deficit_permille: 0,
            inactivation_pressure_permille,
            overhead_ratio_permille: 0,
            budget_exhausted: false,
        };
    }

    let total_cells = n_rows.saturating_mul(n_cols);
    let density_permille = dense_nonzeros.saturating_mul(1000) / total_cells.max(1);
    let rank_deficit_permille = unsupported_cols.saturating_mul(1000) / n_cols;
    let overhead_ratio_permille = n_rows.saturating_sub(n_cols).saturating_mul(1000) / n_cols;

    DecoderPolicyFeatures {
        density_permille,
        rank_deficit_permille,
        inactivation_pressure_permille,
        overhead_ratio_permille,
        budget_exhausted: total_cells > POLICY_FEATURE_BUDGET_CELLS,
    }
}

fn policy_losses(features: DecoderPolicyFeatures, n_cols: usize) -> (u32, u32, u32) {
    let density = clamp_usize_to_u32(features.density_permille);
    let rank_deficit = clamp_usize_to_u32(features.rank_deficit_permille);
    let inactivation_pressure = clamp_usize_to_u32(features.inactivation_pressure_permille);
    let overhead = clamp_usize_to_u32(features.overhead_ratio_permille);

    let baseline_loss = 400u32
        .saturating_add(density.saturating_mul(3))
        .saturating_add(rank_deficit.saturating_mul(4))
        .saturating_add(inactivation_pressure.saturating_mul(2))
        .saturating_add(overhead);

    let high_support_loss = 700u32
        .saturating_add(density)
        .saturating_add(rank_deficit.saturating_mul(3))
        .saturating_add(inactivation_pressure)
        .saturating_add(overhead / 2);

    let block_schur_loss = if n_cols < BLOCK_SCHUR_MIN_COLS {
        u32::MAX
    } else {
        750u32
            .saturating_add(density / 2)
            .saturating_add(rank_deficit.saturating_mul(2))
            .saturating_add(inactivation_pressure)
            .saturating_add(overhead / 3)
    };

    (baseline_loss, high_support_loss, block_schur_loss)
}

#[cfg(test)]
thread_local! {
    static TEST_BYPASS_GOVERNANCE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

#[cfg(test)]
fn set_test_bypass_governance(bypass: bool) {
    TEST_BYPASS_GOVERNANCE.with(|cell| cell.set(bypass));
}

fn bypass_governance() -> bool {
    #[cfg(test)]
    {
        TEST_BYPASS_GOVERNANCE.with(std::cell::Cell::get)
    }
    #[cfg(not(test))]
    {
        false
    }
}

fn choose_runtime_decoder_policy(
    n_rows: usize,
    n_cols: usize,
    dense_nonzeros: usize,
    unsupported_cols: usize,
    inactivation_pressure_permille: usize,
) -> DecoderPolicyDecision {
    let features = compute_decoder_policy_features(
        n_rows,
        n_cols,
        dense_nonzeros,
        unsupported_cols,
        inactivation_pressure_permille,
    );
    let mut decision = choose_low_level_decoder_policy(features, n_rows, n_cols);
    let governance = decision_contract::evaluate_governance(&GovernanceSnapshot {
        n_rows,
        n_cols,
        density_permille: features.density_permille,
        rank_deficit_permille: features.rank_deficit_permille,
        inactivation_pressure_permille: features.inactivation_pressure_permille,
        overhead_ratio_permille: features.overhead_ratio_permille,
        budget_exhausted: features.budget_exhausted,
        baseline_loss: decision.baseline_loss,
        high_support_loss: decision.high_support_loss,
        block_schur_loss: decision.block_schur_loss,
    });
    if !bypass_governance() {
        match governance.chosen_action {
            "canary_hold" if matches!(decision.mode, DecoderPolicyMode::BlockSchurLowRank) => {
                decision.mode = DecoderPolicyMode::HighSupportFirst;
                decision.reason = "g7_expected_loss_canary_hold";
            }
            "rollback" if !matches!(decision.mode, DecoderPolicyMode::ConservativeBaseline) => {
                decision.mode = DecoderPolicyMode::ConservativeBaseline;
                decision.reason = "g7_expected_loss_rollback";
            }
            "fallback" if !matches!(decision.mode, DecoderPolicyMode::ConservativeBaseline) => {
                decision.mode = DecoderPolicyMode::ConservativeBaseline;
                decision.reason = "g7_deterministic_fallback_trigger";
            }
            _ => {}
        }
    }
    decision.governance = Some(governance);
    decision
}

fn choose_low_level_decoder_policy(
    features: DecoderPolicyFeatures,
    n_rows: usize,
    n_cols: usize,
) -> DecoderPolicyDecision {
    let (baseline_loss, high_support_loss, mut block_schur_loss) = policy_losses(features, n_cols);
    if features.budget_exhausted {
        return DecoderPolicyDecision {
            mode: DecoderPolicyMode::ConservativeBaseline,
            features,
            baseline_loss,
            high_support_loss,
            block_schur_loss,
            reason: "policy_budget_exhausted_conservative",
            governance: None,
        };
    }

    let hard_gate = n_cols >= HARD_REGIME_MIN_COLS
        && (features.density_permille >= HARD_REGIME_DENSITY_PERCENT.saturating_mul(10)
            || n_rows <= n_cols.saturating_add(HARD_REGIME_NEAR_SQUARE_EXTRA_ROWS));
    if !hard_gate {
        return DecoderPolicyDecision {
            mode: DecoderPolicyMode::ConservativeBaseline,
            features,
            baseline_loss,
            high_support_loss,
            block_schur_loss,
            reason: "expected_loss_conservative_gate",
            governance: None,
        };
    }

    let block_gate = n_cols >= BLOCK_SCHUR_MIN_COLS
        && features.density_permille >= BLOCK_SCHUR_MIN_DENSITY_PERCENT.saturating_mul(10)
        && n_cols > BLOCK_SCHUR_TRAILING_COLS;
    if !block_gate {
        block_schur_loss = u32::MAX;
    }
    let mode = if block_schur_loss < high_support_loss {
        DecoderPolicyMode::BlockSchurLowRank
    } else {
        DecoderPolicyMode::HighSupportFirst
    };

    DecoderPolicyDecision {
        mode,
        features,
        baseline_loss,
        high_support_loss,
        block_schur_loss,
        reason: "expected_loss_minimum",
        governance: None,
    }
}

const fn decoder_policy_mode_label(mode: DecoderPolicyMode) -> &'static str {
    match mode {
        DecoderPolicyMode::ConservativeBaseline => "conservative_baseline",
        DecoderPolicyMode::HighSupportFirst => "high_support_first",
        DecoderPolicyMode::BlockSchurLowRank => "block_schur_low_rank",
    }
}

fn apply_policy_decision_to_stats(stats: &mut DecodeStats, decision: &DecoderPolicyDecision) {
    stats.policy_mode = Some(decoder_policy_mode_label(decision.mode));
    stats.policy_reason = Some(decision.reason);
    stats.policy_replay_ref = Some(POLICY_REPLAY_REF);
    stats.governance = decision.governance;
    stats.policy_density_permille = decision.features.density_permille;
    stats.policy_rank_deficit_permille = decision.features.rank_deficit_permille;
    stats.policy_inactivation_pressure_permille = decision.features.inactivation_pressure_permille;
    stats.policy_overhead_ratio_permille = decision.features.overhead_ratio_permille;
    stats.policy_budget_exhausted = decision.features.budget_exhausted;
    stats.policy_baseline_loss = decision.baseline_loss;
    stats.policy_high_support_loss = decision.high_support_loss;
    stats.policy_block_schur_loss = decision.block_schur_loss;
}

#[derive(Debug, Clone, Copy)]
struct DenseFactorCacheObservation {
    key: u64,
    result: DenseFactorCacheResult,
    reason: &'static str,
    reuse_eligible: bool,
    fingerprint_collision: bool,
    cache_entries: usize,
    cache_capacity: usize,
}

fn apply_dense_factor_cache_observation(
    stats: &mut DecodeStats,
    observation: DenseFactorCacheObservation,
) {
    stats.factor_cache_last_key = Some(observation.key);
    stats.factor_cache_last_reason = Some(observation.reason);
    stats.factor_cache_last_reuse_eligible = Some(observation.reuse_eligible);
    stats.factor_cache_entries = observation.cache_entries;
    stats.factor_cache_capacity = observation.cache_capacity;
    if observation.fingerprint_collision {
        stats.factor_cache_lookup_collisions += 1;
    }

    match observation.result {
        DenseFactorCacheResult::Hit => {
            stats.factor_cache_hits += 1;
        }
        DenseFactorCacheResult::MissInserted => {
            stats.factor_cache_misses += 1;
            stats.factor_cache_inserts += 1;
        }
        DenseFactorCacheResult::MissEvicted => {
            stats.factor_cache_misses += 1;
            stats.factor_cache_inserts += 1;
            stats.factor_cache_evictions += 1;
        }
    }
}

fn row_nonzero_count(a: &[Gf256], n_cols: usize, row: usize) -> usize {
    let row_off = row * n_cols;
    a[row_off..row_off.saturating_add(n_cols)]
        .iter()
        .filter(|coef| !coef.is_zero())
        .count()
}

fn sparse_update_column_capacity(n_cols: usize) -> usize {
    if n_cols == 0 {
        return 0;
    }

    let threshold =
        n_cols.saturating_mul(HYBRID_SPARSE_COST_NUMERATOR) / HYBRID_SPARSE_COST_DENOMINATOR;
    threshold.max(1).min(n_cols)
}

fn sparse_update_columns_if_beneficial(
    pivot_row: &[Gf256],
    n_cols: usize,
    scratch: &mut Vec<usize>,
) -> bool {
    if n_cols == 0 {
        scratch.clear();
        return false;
    }

    // Equivalent threshold to should_use_sparse_row_update(pivot_nnz, n_cols).
    let threshold =
        n_cols.saturating_mul(HYBRID_SPARSE_COST_NUMERATOR) / HYBRID_SPARSE_COST_DENOMINATOR;
    scratch.clear();

    if n_cols <= SMALL_ROW_DENSE_FASTPATH_COLS {
        // Very small rows are sensitive to per-pivot heap allocation overhead.
        // Use an allocation-free density pass; collect columns only if sparse.
        let mut sparse_nnz = 0usize;
        for coef in pivot_row.iter().take(n_cols) {
            if coef.is_zero() {
                continue;
            }
            sparse_nnz += 1;
            if sparse_nnz > threshold {
                scratch.clear();
                return false;
            }
        }

        for (idx, coef) in pivot_row.iter().take(n_cols).enumerate() {
            if !coef.is_zero() {
                scratch.push(idx);
            }
        }
        return true;
    }

    // For larger rows, one-pass collection avoids an extra scan on sparse pivots.
    let mut seen = 0usize;
    for (idx, coef) in pivot_row.iter().take(n_cols).enumerate() {
        if coef.is_zero() {
            continue;
        }
        seen += 1;
        if seen > threshold {
            scratch.clear();
            return false;
        }
        scratch.push(idx);
    }
    true
}

fn select_hard_regime_plan(n_rows: usize, n_cols: usize, a: &[Gf256]) -> HardRegimePlan {
    let total_cells = n_rows.saturating_mul(n_cols);
    if n_cols < BLOCK_SCHUR_MIN_COLS || total_cells == 0 {
        return HardRegimePlan::Markowitz;
    }
    let nonzeros = matrix_nonzero_count(a);
    let dense_enough =
        nonzeros.saturating_mul(100) >= total_cells.saturating_mul(BLOCK_SCHUR_MIN_DENSITY_PERCENT);
    if !dense_enough || n_cols <= BLOCK_SCHUR_TRAILING_COLS {
        return HardRegimePlan::Markowitz;
    }
    let split_col = n_cols - BLOCK_SCHUR_TRAILING_COLS;
    HardRegimePlan::BlockSchurLowRank { split_col }
}

fn row_cross_block_nnz(
    a: &[Gf256],
    n_cols: usize,
    row: usize,
    split_col: usize,
    col: usize,
) -> usize {
    let row_off = row * n_cols;
    let row_slice = &a[row_off..row_off + n_cols];
    if col < split_col {
        row_slice[split_col..]
            .iter()
            .filter(|coef| !coef.is_zero())
            .count()
    } else {
        row_slice[..split_col]
            .iter()
            .filter(|coef| !coef.is_zero())
            .count()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PivotCandidate {
    row: usize,
    cross_block_nnz: usize,
    row_nnz: usize,
}

impl PivotCandidate {
    fn is_better_than(self, other: Self) -> bool {
        (self.cross_block_nnz, self.row_nnz, self.row)
            < (other.cross_block_nnz, other.row_nnz, other.row)
    }
}

fn select_pivot_row(
    a: &[Gf256],
    n_rows: usize,
    n_cols: usize,
    col: usize,
    row_used: &[bool],
    hard_regime: bool,
    hard_plan: HardRegimePlan,
) -> Option<usize> {
    if !hard_regime {
        return (0..n_rows).find(|&row| !row_used[row] && !a[row * n_cols + col].is_zero());
    }

    let mut best: Option<PivotCandidate> = None;
    for row in 0..n_rows {
        if row_used[row] || a[row * n_cols + col].is_zero() {
            continue;
        }
        let cross_block_nnz = match hard_plan {
            HardRegimePlan::Markowitz => 0,
            HardRegimePlan::BlockSchurLowRank { split_col } => {
                row_cross_block_nnz(a, n_cols, row, split_col, col)
            }
        };
        let nnz = row_nonzero_count(a, n_cols, row);
        let candidate = PivotCandidate {
            row,
            cross_block_nnz,
            row_nnz: nnz,
        };
        match best {
            None => best = Some(candidate),
            Some(best_candidate) if candidate.is_better_than(best_candidate) => {
                best = Some(candidate);
            }
            _ => {}
        }
    }

    best.map(|candidate| candidate.row)
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
    dense_factor_cache: parking_lot::Mutex<DenseFactorCache>,
    /// Rate limiting for ESI/ObjectId combinations to prevent amplification attacks.
    ///
    /// br-asupersync-ju2k01: Tracks ESI access patterns and compute budget
    /// consumption to detect and block malicious ESI values near u32::MAX
    /// that can cause expensive O(L³) Gaussian elimination operations.
    esi_rate_limits: parking_lot::Mutex<HashMap<(u32, ObjectId), EsiRateLimit>>,
}

impl InactivationDecoder {
    /// Create a new decoder for the given parameters.
    ///
    /// br-asupersync-cjv6x4: PANICS for `k == 0` or `k > 56403` (the
    /// upper bound of RFC 6330's systematic-index table). Callers
    /// that handle attacker-influenced FEC-OTI parameters and want
    /// graceful error handling MUST use [`Self::try_new`] instead,
    /// which returns `Result<Self, SystematicParamError>`.
    #[must_use]
    pub fn new(k: usize, symbol_size: usize, seed: u64) -> Self {
        let params = SystematicParams::for_source_block(k, symbol_size);
        Self {
            params,
            seed,
            dense_factor_cache: parking_lot::Mutex::new(DenseFactorCache::default()),
            esi_rate_limits: parking_lot::Mutex::new(HashMap::new()),
        }
    }

    /// br-asupersync-cjv6x4: fallible variant of [`Self::new`] that
    /// returns `Err(SystematicParamError::UnsupportedSourceBlockSize)`
    /// for `k == 0` or `k > 56403` instead of panicking. Use this
    /// from network-receivable decode paths where the FEC-OTI K
    /// arrives from an attacker-influenced source.
    pub fn try_new(
        k: usize,
        symbol_size: usize,
        seed: u64,
    ) -> Result<Self, crate::raptorq::systematic::SystematicParamError> {
        let params =
            crate::raptorq::systematic::SystematicParams::try_for_source_block(k, symbol_size)?;
        Ok(Self {
            params,
            seed,
            dense_factor_cache: parking_lot::Mutex::new(DenseFactorCache::default()),
            esi_rate_limits: parking_lot::Mutex::new(HashMap::new()),
        })
    }

    /// Returns the encoding parameters.
    #[must_use]
    #[inline]
    pub const fn params(&self) -> &SystematicParams {
        &self.params
    }

    #[inline]
    const fn implicit_padding_rows(&self) -> usize {
        self.params.k_prime.saturating_sub(self.params.k)
    }

    #[inline]
    const fn minimum_received_symbols(&self) -> usize {
        self.params.l.saturating_sub(self.implicit_padding_rows())
    }

    /// Return the per-decode compute ceiling for the admitted source-block shape.
    ///
    /// A minimally sufficient block can contain [`Self::minimum_received_symbols`]
    /// equations. Each valid RFC 6330 tuple expands to at most 32 columns, and
    /// the admission estimate charges the square of that width. Scaling the
    /// ceiling by the block dimensions admits every minimal valid block while
    /// retaining a finite allowance for surplus or adversarial rows.
    fn dense_compute_budget_limit(&self) -> u64 {
        let block_budget = u64::try_from(self.minimum_received_symbols())
            .unwrap_or(u64::MAX)
            .saturating_mul(MAX_RFC6330_COLUMNS_PER_ESI.saturating_pow(2));
        block_budget.max(MIN_DENSE_COMPUTE_BUDGET)
    }

    /// Validate ESI value against compute and amplification attack limits.
    ///
    /// br-asupersync-ju2k01: Prevents RaptorQ decoder amplification DoS attacks
    /// by checking for malicious ESI values near u32::MAX that can cause
    /// expensive O(L³) Gaussian elimination operations.
    fn validate_esi_admission(
        &self,
        esi: u32,
        object_id: Option<&ObjectId>,
        compute_budget: &mut ComputeBudget,
    ) -> Result<(), DecodeError> {
        // Check for ESI values that are suspiciously large
        if esi > MAX_ALLOWED_ESI {
            return Err(DecodeError::EsiRateLimitExceeded {
                esi,
                column_count: 0,
                max_columns: MAX_COLUMNS_PER_ESI,
            });
        }

        // Estimate compute cost for this ESI based on column generation
        let columns = repair_indices_for_esi(self.params.j, self.params.w, self.params.p, esi);

        // Check if this ESI would generate too many columns (matrix blow-up)
        if columns.len() > MAX_COLUMNS_PER_ESI {
            return Err(DecodeError::EsiRateLimitExceeded {
                esi,
                column_count: columns.len(),
                max_columns: MAX_COLUMNS_PER_ESI,
            });
        }

        // Estimate compute budget needed: O(columns²) for dense operations
        let estimated_cost = (columns.len() as u64).saturating_pow(2);
        compute_budget.consume(estimated_cost)?;

        // Structural and per-call compute admission is identical for every
        // decode entry point. ObjectId only enables cross-call rate accounting.
        let Some(object_id) = object_id else {
            return Ok(());
        };

        // Update rate limiting state.
        let key = (esi, *object_id);
        let mut rate_limits = self.esi_rate_limits.lock();
        let now = Instant::now();

        let entry = rate_limits.entry(key).or_default();

        // Reset access count if enough time has passed (simple time window)
        if now.duration_since(entry.last_access) > Duration::from_secs(60) {
            entry.access_count = 0;
            entry.compute_budget_used = 0;
        }

        entry.last_access = now;
        entry.access_count = entry.access_count.saturating_add(1);
        entry.compute_budget_used = entry.compute_budget_used.saturating_add(estimated_cost);

        // Check rate limits: max 100 accesses per ESI/ObjectId per minute
        if entry.access_count > 100 {
            return Err(DecodeError::EsiRateLimitExceeded {
                esi,
                column_count: columns.len(),
                max_columns: MAX_COLUMNS_PER_ESI,
            });
        }

        // Check compute budget per ESI
        if entry.compute_budget_used > MIN_DENSE_COMPUTE_BUDGET / 10 {
            return Err(DecodeError::ComputeBudgetExhausted {
                used: entry.compute_budget_used,
                requested: estimated_cost,
                max: MIN_DENSE_COMPUTE_BUDGET / 10,
            });
        }

        Ok(())
    }

    fn validate_input(
        &self,
        symbols: &[ReceivedSymbol],
        object_id: Option<&ObjectId>,
    ) -> Result<(), DecodeError> {
        let l = self.params.l;
        let symbol_size = self.params.symbol_size;
        let required = self.minimum_received_symbols();

        // br-asupersync-ju2k01: Create a block-scaled compute budget for dense
        // operations. This admission policy must not depend on proof capture or
        // the presence of an ObjectId.
        let mut compute_budget = ComputeBudget::new(self.dense_compute_budget_limit());
        let mut seen_source_payloads = HashMap::with_capacity(self.params.k.min(symbols.len()));
        let mut seen_equation_payloads = SeenEquationPayloads::with_capacity(symbols.len());

        for sym in symbols {
            if sym.data.len() != symbol_size {
                return Err(DecodeError::SymbolSizeMismatch {
                    expected: symbol_size,
                    actual: sym.data.len(),
                });
            }

            if sym.columns.len() != sym.coefficients.len() {
                return Err(DecodeError::SymbolEquationArityMismatch {
                    esi: sym.esi,
                    columns: sym.columns.len(),
                    coefficients: sym.coefficients.len(),
                });
            }

            // br-asupersync-ju2k01: Validate every decode entry point against
            // amplification attacks; ObjectId only keys cross-call accounting.
            self.validate_esi_admission(sym.esi, object_id, &mut compute_budget)?;

            self.validate_source_symbol_equation(sym)?;
            self.validate_symbol_payload_consistency(
                sym,
                &mut seen_source_payloads,
                &mut seen_equation_payloads,
            )?;

            for &column in &sym.columns {
                if column >= l {
                    return Err(DecodeError::ColumnIndexOutOfRange {
                        esi: sym.esi,
                        column,
                        max_valid: l,
                    });
                }
            }
        }

        if symbols.len() < required {
            return Err(DecodeError::InsufficientSymbols {
                received: symbols.len(),
                required,
            });
        }

        Ok(())
    }

    fn validate_symbol_payload_consistency<'a>(
        &self,
        sym: &'a ReceivedSymbol,
        seen_source_payloads: &mut HashMap<u32, &'a [u8]>,
        seen_equation_payloads: &mut SeenEquationPayloads<'a>,
    ) -> Result<(), DecodeError> {
        let payload = sym.data.as_slice();
        if sym.is_source {
            if let Some(expected_payload) = seen_source_payloads.get(&sym.esi).copied() {
                return Self::validate_payload_against_prior(sym.esi, payload, expected_payload);
            }
            seen_source_payloads.insert(sym.esi, payload);
            return Ok(());
        }

        let same_esi_payloads = seen_equation_payloads.entry(sym.esi).or_default();
        for &(columns, coefficients, expected_payload) in same_esi_payloads.iter() {
            if columns == sym.columns.as_slice() && coefficients == sym.coefficients.as_slice() {
                return Self::validate_payload_against_prior(sym.esi, payload, expected_payload);
            }
        }
        same_esi_payloads.push((sym.columns.as_slice(), sym.coefficients.as_slice(), payload));

        Ok(())
    }

    fn validate_payload_against_prior(
        esi: u32,
        payload: &[u8],
        expected_payload: &[u8],
    ) -> Result<(), DecodeError> {
        if let Some(byte_index) = first_mismatch_byte(expected_payload, payload) {
            return Err(DecodeError::CorruptDecodedOutput {
                esi,
                byte_index,
                expected: expected_payload[byte_index],
                actual: payload[byte_index],
            });
        }

        Ok(())
    }

    fn verify_decoded_output(
        &self,
        symbols: &[ReceivedSymbol],
        intermediate: &[Option<Vec<u8>>],
    ) -> Result<(), DecodeError> {
        let symbol_size = self.params.symbol_size;
        // Reuse a single scratch buffer across rows to avoid per-symbol
        // heap allocation in decode hot paths.
        let mut reconstructed = vec![0u8; symbol_size];

        for sym in symbols {
            if sym.data.len() != symbol_size {
                return Err(DecodeError::SymbolSizeMismatch {
                    expected: symbol_size,
                    actual: sym.data.len(),
                });
            }
            reconstructed.fill(0);
            let source_equation_storage;
            let (columns, coefficients): (&[usize], &[Gf256]) = if sym.is_source {
                source_equation_storage = self.source_equation(sym.esi);
                (&source_equation_storage.0, &source_equation_storage.1)
            } else {
                (&sym.columns, &sym.coefficients)
            };
            for (&column, &coefficient) in columns.iter().zip(coefficients.iter()) {
                if coefficient.is_zero() {
                    continue;
                }
                let symbol = require_intermediate_symbol(intermediate, column, symbol_size)?;
                gf256_addmul_slice(&mut reconstructed, symbol, coefficient);
            }
            if let Some(byte_index) = first_mismatch_byte(&reconstructed, &sym.data) {
                return Err(DecodeError::CorruptDecodedOutput {
                    esi: sym.esi,
                    byte_index,
                    expected: reconstructed[byte_index],
                    actual: sym.data[byte_index],
                });
            }
        }

        Ok(())
    }

    /// Decode from received symbols.
    ///
    /// `symbols` must include the LDPC/HDPC constraint rows and enough received
    /// equations to solve the block. The decoder synthesizes the implicit zero
    /// LT rows for the padded systematic range `K..K'`, so callers do not need
    /// to supply them explicitly.
    /// Returns the decoded source symbols on success.
    pub fn decode(&self, symbols: &[ReceivedSymbol]) -> Result<DecodeResult, DecodeError> {
        self.decode_with_object_id(symbols, None)
    }

    /// Decode with ObjectId for rate limiting against amplification attacks.
    ///
    /// br-asupersync-ju2k01: Extended decode method that includes ObjectId
    /// for rate limiting ESI/ObjectId combinations to prevent RaptorQ
    /// decoder amplification DoS attacks via malicious ESI values.
    pub fn decode_with_object_id(
        &self,
        symbols: &[ReceivedSymbol],
        object_id: Option<&ObjectId>,
    ) -> Result<DecodeResult, DecodeError> {
        self.validate_input(symbols, object_id)?;

        // Build decoder state
        let mut state = self.build_state(symbols);

        // Phase 1: Peeling
        Self::peel(&mut state);

        // Phase 2: Inactivation + Gaussian elimination
        self.inactivate_and_solve(&mut state)?;

        let DecoderState { solved, stats, .. } = state;
        self.verify_decoded_output(symbols, &solved)?;
        let source = self.reconstruct_source_symbols(&solved)?;
        let intermediate = self.materialize_intermediate_symbols(solved)?;

        Ok(DecodeResult {
            intermediate,
            source,
            stats,
        })
    }

    /// Compute the current GF(256) equation rank without solving RHS data.
    ///
    /// The returned deficit mirrors the decoder's full system shape: caller-supplied
    /// constraint/received rows plus the same implicit K..K' padding rows that
    /// [`Self::decode`] synthesizes. A deficit of zero means the equation matrix
    /// is full-rank; it does not by itself verify RHS consistency.
    pub fn rank_status(&self, symbols: &[ReceivedSymbol]) -> Result<RankStatus, DecodeError> {
        let profile = self.rank_profile(symbols)?;
        Ok(RankStatus {
            rank: profile.rank,
            columns: profile.columns,
            deficit: profile.deficit,
        })
    }

    /// Compute the deterministic pivot/free-column rank profile for a received
    /// block equation set.
    ///
    /// This uses the same full decoder system shape as [`Self::rank_status`]:
    /// caller-supplied equations plus the implicit K..K' padding rows. The
    /// profile is diagnostic only; decode success still requires RHS
    /// consistency and decoded-output verification.
    pub fn rank_profile(
        &self,
        symbols: &[ReceivedSymbol],
    ) -> Result<GaussianRankProfile, DecodeError> {
        self.validate_rank_input(symbols)?;
        let state = self.build_state(symbols);
        Ok(equation_rank_profile(&state.equations, self.params.l))
    }

    /// Decode using the bounded wavefront pipeline.
    ///
    /// Instead of sequential assembly→peel→solve, this pipeline fuses
    /// assembly and peeling into bounded batches: symbols are assembled in
    /// chunks of `batch_size`, and after each chunk the peeling queue is
    /// drained. This reduces pipeline bubbles by overlapping assembly with
    /// peeling, so degree-1 equations discovered early are solved while
    /// remaining symbols are still being assembled.
    ///
    /// The solve phase (inactivation + Gaussian elimination) runs after
    /// all batches are processed, identical to the sequential path.
    ///
    /// Correctness: produces identical results to `decode()` because
    /// peeling order is deterministic (FIFO queue, same equation ordering)
    /// and the dense solve phase sees the same final state.
    ///
    /// `batch_size` controls the wavefront width. Smaller batches increase
    /// overlap but add per-batch overhead. A batch size of 0 means "use
    /// all symbols at once" (equivalent to sequential mode).
    pub fn decode_wavefront(
        &self,
        symbols: &[ReceivedSymbol],
        batch_size: usize,
    ) -> Result<DecodeResult, DecodeError> {
        self.validate_input(symbols, None)?;

        // A batch_size of 0 falls back to sequential (single batch = all symbols).
        let effective_batch = if batch_size == 0 {
            symbols.len()
        } else {
            batch_size
        };

        // Start from the same implicit K..K' padding rows that the sequential
        // decoder synthesizes so wavefront mode remains RFC-parity equivalent
        // on padded parameter sets.
        let mut state = self.build_state(&[]);
        state.equations.reserve(symbols.len());
        state.rhs.reserve(symbols.len());
        state.stats.wavefront_active = true;
        state.stats.wavefront_batch_size = effective_batch;

        // Wavefront: assemble symbols in bounded batches and peel after each.
        let mut total_overlap_peeled = 0usize;
        let mut batch_count = 0usize;
        let mut queue = VecDeque::new();
        let mut queued = vec![false; state.equations.len()];

        // The synthesized K..K' padding rows are immediately available and may
        // peel before any real symbols arrive. Apply that deterministic prefix
        // up front so subsequent batch catch-up sees the same reduced state as
        // the sequential decode path.
        for (idx, queued_flag) in queued.iter_mut().enumerate() {
            if !*queued_flag && active_degree_one_col(&state, &state.equations[idx]).is_some() {
                queue.push_back(idx);
                *queued_flag = true;
                state.stats.peel_queue_pushes += 1;
            }
        }
        state.stats.peel_frontier_peak = state.stats.peel_frontier_peak.max(queue.len());
        Self::peel_from_queue(&mut state, &mut queue, &mut queued);

        let mut solved_terms = Vec::new();
        for chunk in symbols.chunks(effective_batch) {
            let base_eq_idx = state.equations.len();
            // Assembly: add this batch of symbols as equations.
            for sym in chunk {
                state.equations.push(self.received_symbol_equation(sym));
                state.rhs.push(sym.data.clone());
            }
            queued.resize(state.equations.len(), false);

            // Catch-up: apply already-peeled solutions to newly assembled equations.
            // This ensures new equations see the same reduced state they would in
            // the sequential path where all equations are present before peeling.
            let solved = &state.solved;
            for idx in base_eq_idx..state.equations.len() {
                state.equations[idx].extract_solved_terms(solved, &mut solved_terms);
                for &(col, eq_coef) in &solved_terms {
                    let solution = solved[col].as_ref().expect("solution must exist");
                    gf256_addmul_slice(&mut state.rhs[idx], solution, eq_coef);
                }
            }

            // Scan newly added equations for degree-1 candidates.
            for (idx, queued_flag) in queued.iter_mut().enumerate().skip(base_eq_idx) {
                if !*queued_flag && active_degree_one_col(&state, &state.equations[idx]).is_some() {
                    queue.push_back(idx);
                    *queued_flag = true;
                    state.stats.peel_queue_pushes += 1;
                }
            }
            state.stats.peel_frontier_peak = state.stats.peel_frontier_peak.max(queue.len());

            // Peel: drain the queue after this batch.
            let peeled_before = state.stats.peeled;
            Self::peel_from_queue(&mut state, &mut queue, &mut queued);
            let peeled_this_batch = state.stats.peeled - peeled_before;
            if batch_count > 0 {
                // Only count overlap peeling from non-first batches,
                // since the first batch has no prior assembly to overlap with.
                total_overlap_peeled += peeled_this_batch;
            }
            batch_count += 1;
        }

        state.stats.wavefront_batches = batch_count;
        state.stats.wavefront_overlap_peeled = total_overlap_peeled;

        // Phase 2: Inactivation + Gaussian elimination (same as sequential).
        self.inactivate_and_solve(&mut state)?;

        let DecoderState { solved, stats, .. } = state;
        self.verify_decoded_output(symbols, &solved)?;
        let source = self.reconstruct_source_symbols(&solved)?;
        let intermediate = self.materialize_intermediate_symbols(solved)?;

        Ok(DecodeResult {
            intermediate,
            source,
            stats,
        })
    }

    /// Peel from an existing queue, extending as new degree-1 equations are discovered.
    ///
    /// This is the core peeling loop factored out so it can be called
    /// incrementally by the wavefront pipeline after each assembly batch.
    fn peel_from_queue(state: &mut DecoderState, queue: &mut VecDeque<usize>, queued: &mut [bool]) {
        while let Some(eq_idx) = queue.pop_front() {
            state.stats.peel_queue_pops += 1;
            queued[eq_idx] = false;

            let Some(col) = active_degree_one_col(state, &state.equations[eq_idx]) else {
                continue;
            };

            // Solve this equation.
            let (_col, coef) = state.equations[eq_idx].terms[0];
            state.equations[eq_idx].used = true;

            let mut solution = std::mem::take(&mut state.rhs[eq_idx]);
            if coef != Gf256::ONE {
                let inv = coef.inv();
                crate::raptorq::gf256::gf256_mul_slice(&mut solution, inv);
            }

            state.column_states[col] = ColumnState::Solved;
            state.stats.peeled += 1;

            // Propagate to other equations.
            // Note: direct state.column_states[next_col] access replaces active_cols.contains()
            let solved = &state.solved;
            for (i, (eq, rhs)) in state
                .equations
                .iter_mut()
                .zip(state.rhs.iter_mut())
                .enumerate()
            {
                if eq.used {
                    continue;
                }
                let Some(eq_coef) = eq.take_coef(col) else {
                    continue;
                };
                gf256_addmul_slice(rhs, &solution, eq_coef);

                if !queued[i] && eq.degree() == 1 {
                    let next_col = eq.terms[0].0;
                    if state.column_states[next_col] == ColumnState::Active
                        && solved[next_col].is_none()
                    {
                        queue.push_back(i);
                        queued[i] = true;
                        state.stats.peel_queue_pushes += 1;
                    }
                }
            }

            state.stats.peel_frontier_peak = state.stats.peel_frontier_peak.max(queue.len());
            state.solved[col] = Some(solution);
        }
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
        let k = self.params.k;
        let symbol_size = self.params.symbol_size;

        // Build proof configuration
        let config = DecodeConfig {
            object_id,
            sbn,
            k,
            s: self.params.s,
            h: self.params.h,
            l: self.params.l,
            symbol_size,
            seed: self.seed,
        };
        let mut proof_builder = DecodeProof::builder(config);

        // Capture received symbols summary
        let received = ReceivedSummary::from_received(symbols.iter().map(|s| (s.esi, s.is_source)));
        proof_builder.set_received(received);

        // Validate input
        if let Err(err) = self.validate_input(symbols, Some(&object_id)) {
            proof_builder.set_failure(FailureReason::from(&err));
            return Err((err, proof_builder.build()));
        }

        // Build decoder state
        let mut state = self.build_state(symbols);

        // Phase 1: Peeling with proof capture
        Self::peel_with_proof(&mut state, proof_builder.peeling_mut());

        // Phase 2: Inactivation + Gaussian elimination with proof capture
        if let Err(err) =
            self.inactivate_and_solve_with_proof(&mut state, proof_builder.elimination_mut())
        {
            let reason = failure_reason_with_trace(&err, proof_builder.elimination_mut());
            proof_builder.set_failure(reason);
            return Err((err, proof_builder.build()));
        }

        let DecoderState { solved, stats, .. } = state;
        if let Err(err) = self.verify_decoded_output(symbols, &solved) {
            proof_builder.set_failure(FailureReason::from(&err));
            return Err((err, proof_builder.build()));
        }

        let source = match self.reconstruct_source_symbols(&solved) {
            Ok(source) => source,
            Err(err) => {
                proof_builder.set_failure(FailureReason::from(&err));
                return Err((err, proof_builder.build()));
            }
        };
        let intermediate = match self.materialize_intermediate_symbols(solved) {
            Ok(intermediate) => intermediate,
            Err(err) => {
                proof_builder.set_failure(FailureReason::from(&err));
                return Err((err, proof_builder.build()));
            }
        };

        // Mark success with a deterministic binding to the recovered payload.
        proof_builder.set_success(&source);

        Ok(DecodeResultWithProof {
            result: DecodeResult {
                intermediate,
                source,
                stats,
            },
            proof: proof_builder.build(),
        })
    }

    /// Build initial decoder state from received symbols.
    ///
    /// The caller is responsible for including LDPC/HDPC constraint equations
    /// (with zero RHS) in the received symbols if needed. The decoder
    /// synthesizes the implicit zero LT rows for the padded systematic range
    /// `K..K'` so direct callers cannot accidentally omit them.
    fn build_state(&self, symbols: &[ReceivedSymbol]) -> DecoderState {
        let l = self.params.l;
        let symbol_size = self.params.symbol_size;

        let mut equations = Vec::with_capacity(symbols.len() + self.implicit_padding_rows());
        let mut rhs = Vec::with_capacity(symbols.len() + self.implicit_padding_rows());

        // Add received symbol equations
        for sym in symbols {
            equations.push(self.received_symbol_equation(sym));
            rhs.push(sym.data.clone());
        }

        // Systematic encoding includes K' LT rows. When K' > K the encoder
        // appends padded LT rows K..K' with an explicit zero RHS; synthesize
        // those rows here so the direct decoder path matches the encoder's
        // constraint system even when callers only provide real source symbols.
        for esi in self.params.k..self.params.k_prime {
            // Skip ESIs that don't fit in u32 to avoid panic (extremely large k_prime)
            if let Ok(esi_u32) = u32::try_from(esi) {
                let (columns, coefficients) = self.systematic_equation(esi_u32);
                equations.push(Equation::new(columns, coefficients));
                rhs.push(vec![0u8; symbol_size]);
            }
            // Note: skipping out-of-range ESIs may affect decoding correctness
            // for pathological parameter combinations
        }

        DecoderState {
            params: self.params.clone(),
            equations,
            rhs,
            solved: vec![None; l],
            column_states: vec![ColumnState::Active; l],
            stats: DecodeStats::default(),
        }
    }

    fn dense_factor_with_cache(
        &self,
        equations: &[Equation],
        dense_rows: &[usize],
        unsolved: &[usize],
    ) -> (Arc<DenseFactorArtifact>, DenseFactorCacheObservation) {
        let signature = DenseFactorSignature::from_equations(equations, dense_rows, unsolved);
        let cache_key = signature.fingerprint;
        let (lookup, cache_entries_at_lookup) = {
            let cache = self.dense_factor_cache.lock();
            (cache.lookup(&signature), cache.len())
        };

        if let DenseFactorCacheLookup::Hit(artifact) = lookup {
            return (
                artifact,
                DenseFactorCacheObservation {
                    key: cache_key,
                    result: DenseFactorCacheResult::Hit,
                    reason: "signature_match_reuse",
                    reuse_eligible: true,
                    fingerprint_collision: false,
                    cache_entries: cache_entries_at_lookup,
                    cache_capacity: DENSE_FACTOR_CACHE_CAPACITY,
                },
            );
        }

        let saw_fingerprint_collision =
            matches!(lookup, DenseFactorCacheLookup::MissFingerprintCollision);
        let artifact = Arc::new(DenseFactorArtifact::new(sparse_first_dense_columns(
            equations, dense_rows, unsolved,
        )));
        let (result, cache_entries) = {
            let mut cache = self.dense_factor_cache.lock();
            let result = cache.insert(signature, Arc::clone(&artifact));
            (result, cache.len())
        };
        let reason = if saw_fingerprint_collision {
            "fingerprint_collision_rebuild"
        } else {
            match result {
                DenseFactorCacheResult::Hit => "signature_match_reuse",
                DenseFactorCacheResult::MissInserted => "cache_miss_rebuild",
                DenseFactorCacheResult::MissEvicted => "cache_miss_evicted_oldest",
            }
        };
        (
            artifact,
            DenseFactorCacheObservation {
                key: cache_key,
                result,
                reason,
                reuse_eligible: false,
                fingerprint_collision: saw_fingerprint_collision,
                cache_entries,
                cache_capacity: DENSE_FACTOR_CACHE_CAPACITY,
            },
        )
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
        Self::peel_impl(state, |_| {});
    }

    /// Phase 1: Peeling with proof trace capture.
    ///
    /// Like `peel`, but also records solved symbols to the proof trace.
    fn peel_with_proof(state: &mut DecoderState, trace: &mut PeelingTrace) {
        Self::peel_impl(state, |col| {
            trace.record_solved(col);
        });
    }

    fn peel_impl<F>(state: &mut DecoderState, mut on_solved: F)
    where
        F: FnMut(usize),
    {
        let mut queue = VecDeque::new();
        let mut queued = vec![false; state.equations.len()];
        for (idx, eq) in state.equations.iter().enumerate() {
            if active_degree_one_col(state, eq).is_some() {
                queue.push_back(idx);
                queued[idx] = true;
                state.stats.peel_queue_pushes += 1;
            }
        }
        state.stats.peel_frontier_peak = state.stats.peel_frontier_peak.max(queue.len());

        while let Some(eq_idx) = queue.pop_front() {
            state.stats.peel_queue_pops += 1;
            queued[eq_idx] = false;

            let Some(col) = active_degree_one_col(state, &state.equations[eq_idx]) else {
                continue;
            };

            // Solve this equation
            let (_col, coef) = state.equations[eq_idx].terms[0];
            state.equations[eq_idx].used = true;

            // Compute the solution: intermediate[col] = rhs[eq_idx] / coef
            let mut solution = std::mem::take(&mut state.rhs[eq_idx]);
            if coef != Gf256::ONE {
                let inv = coef.inv();
                crate::raptorq::gf256::gf256_mul_slice(&mut solution, inv);
            }

            state.column_states[col] = ColumnState::Solved;
            state.stats.peeled += 1;
            on_solved(col);

            // Propagate to other equations: subtract col's contribution
            // Note: direct state.column_states[next_col] access replaces active_cols.contains()
            let solved = &state.solved;
            for (i, eq) in state.equations.iter_mut().enumerate() {
                if eq.used {
                    continue;
                }

                // Fast path: for degree-2 equations, avoid binary search
                if let Some((eq_coef, remaining_col)) = eq.take_coef_degree2_fast(col) {
                    // rhs[i] -= eq_coef * solution
                    gf256_addmul_slice(&mut state.rhs[i], &solution, eq_coef);

                    // We know it's now degree-1 with remaining_col, no need to check
                    if !queued[i]
                        && state.column_states[remaining_col] == ColumnState::Active
                        && solved[remaining_col].is_none()
                    {
                        queue.push_back(i);
                        queued[i] = true;
                        state.stats.peel_queue_pushes += 1;
                    }
                } else {
                    // Fallback to binary search for other degrees
                    let Some(eq_coef) = eq.take_coef(col) else {
                        continue;
                    };
                    // rhs[i] -= eq_coef * solution
                    gf256_addmul_slice(&mut state.rhs[i], &solution, eq_coef);

                    if !queued[i] && !eq.used && eq.degree() == 1 {
                        let next_col = eq.terms[0].0;
                        if state.column_states[next_col] == ColumnState::Active
                            && solved[next_col].is_none()
                        {
                            queue.push_back(i);
                            queued[i] = true;
                            state.stats.peel_queue_pushes += 1;
                        }
                    }
                }
            }

            state.stats.peel_frontier_peak = state.stats.peel_frontier_peak.max(queue.len());

            // Move solution instead of cloning (avoids allocation)
            state.solved[col] = Some(solution);
        }
    }

    /// Phase 2: Inactivation + Gaussian elimination.
    #[allow(clippy::too_many_lines)]
    fn inactivate_and_solve(&self, state: &mut DecoderState) -> Result<(), DecodeError> {
        let symbol_size = self.params.symbol_size;

        // Collect remaining unsolved columns
        let unsolved: Vec<usize> = state
            .column_states
            .iter()
            .enumerate()
            .filter_map(|(col, &state_val)| {
                if state_val == ColumnState::Active && state.solved[col].is_none() {
                    Some(col)
                } else {
                    None
                }
            })
            .collect();

        if unsolved.is_empty() {
            return Ok(());
        }
        state.stats.peeling_fallback_reason = Some("peeling_exhausted_to_dense_core");

        // Collect unused equations
        let unused_eqs: Vec<usize> = state
            .equations
            .iter()
            .enumerate()
            .filter_map(|(i, eq)| if eq.used { None } else { Some(i) })
            .collect();
        let (dense_rows, dropped_zero_rows) = build_dense_core_rows(state, &unused_eqs, &unsolved)?;
        state.stats.dense_core_dropped_rows += dropped_zero_rows;
        validate_dense_core_rhs_widths(state, &dense_rows, symbol_size)?;

        // Mark all remaining unsolved columns as inactive
        for &col in &unsolved {
            state.column_states[col] = ColumnState::Inactive;
            state.stats.inactivated += 1;
        }

        // Reorder dense elimination columns deterministically and reuse cached
        // dense skeleton metadata when signatures match.
        let (dense_factor, cache_observation) =
            self.dense_factor_with_cache(&state.equations, &dense_rows, &unsolved);
        apply_dense_factor_cache_observation(&mut state.stats, cache_observation);
        let dense_cols = &dense_factor.dense_cols;
        let col_to_dense = &dense_factor.col_to_dense;

        // Build dense submatrix for Gaussian elimination
        // Rows = unused equations, Columns = unsolved columns
        let n_rows = dense_rows.len();
        let n_cols = dense_cols.len();
        let inactivation_pressure_permille =
            unsolved.len().saturating_mul(1000) / state.params.l.max(1);
        state.stats.dense_core_rows = n_rows;
        state.stats.dense_core_cols = n_cols;

        let mut b: Vec<Vec<u8>> = Vec::with_capacity(n_rows);

        if n_rows < n_cols {
            reactivate_unsolved_columns(state, &unsolved);
            return Err(singular_matrix_error(&unsolved, n_rows));
        }

        // Build flat row-major dense matrix A and RHS vector b.
        // Flat layout avoids per-row heap allocation and improves cache locality.
        // Move (take) RHS data from state instead of cloning to avoid O(n_rows * symbol_size)
        // heap allocation in this hot path.
        let total_cells = match n_rows.checked_mul(n_cols) {
            Some(total_cells) => total_cells,
            None => {
                let err = DecodeError::InsufficientSymbols {
                    received: n_rows,
                    required: n_cols,
                };
                reactivate_unsolved_columns(state, &unsolved);
                return Err(err);
            }
        };
        let mut a = vec![Gf256::ZERO; total_cells];
        let mut dense_nonzeros = 0usize;
        let mut dense_col_support = vec![0usize; n_cols];

        for (row, &eq_idx) in dense_rows.iter().enumerate() {
            let row_off = row * n_cols;
            for &(col, coef) in &state.equations[eq_idx].terms {
                if let Some(dense_col) = dense_col_index(col_to_dense, col) {
                    a[row_off + dense_col] = coef;
                    if !coef.is_zero() {
                        dense_nonzeros += 1;
                        dense_col_support[dense_col] += 1;
                    }
                }
            }
            b.push(std::mem::take(&mut state.rhs[eq_idx]));
        }
        let unsupported_cols = dense_col_support
            .iter()
            .filter(|&&support| support == 0)
            .count();
        let dense_rhs_snapshot = snapshot_dense_rhs(&b, symbol_size)?;

        let decision = choose_runtime_decoder_policy(
            n_rows,
            n_cols,
            dense_nonzeros,
            unsupported_cols,
            inactivation_pressure_permille,
        );
        apply_policy_decision_to_stats(&mut state.stats, &decision);
        let mut hard_regime = !matches!(decision.mode, DecoderPolicyMode::ConservativeBaseline);
        let mut hard_plan = match decision.mode {
            DecoderPolicyMode::ConservativeBaseline | DecoderPolicyMode::HighSupportFirst => {
                HardRegimePlan::Markowitz
            }
            DecoderPolicyMode::BlockSchurLowRank => select_hard_regime_plan(n_rows, n_cols, &a),
        };
        if hard_regime {
            state.stats.hard_regime_activated = true;
            state.stats.hard_regime_branch = Some(hard_plan.label());
        } else if decision.reason == "policy_budget_exhausted_conservative" {
            state.stats.hard_regime_conservative_fallback_reason = Some(decision.reason);
        }

        let mut pivot_row = vec![usize::MAX; n_cols];
        loop {
            pivot_row.fill(usize::MAX);

            // Gaussian elimination with partial pivoting.
            // Pre-allocate a single pivot buffer to avoid per-column clones.
            let mut row_used = vec![false; n_rows];
            let mut pivot_buf = vec![Gf256::ZERO; n_cols];
            let mut pivot_rhs = vec![0u8; symbol_size];
            let mut sparse_cols_buf = Vec::with_capacity(sparse_update_column_capacity(n_cols));
            let mut gauss_ops = 0usize;
            let mut pivots_selected = 0usize;
            let mut markowitz_pivots = 0usize;
            let mut elimination_error = None;

            for col in 0..n_cols {
                let pivot =
                    select_pivot_row(&a, n_rows, n_cols, col, &row_used, hard_regime, hard_plan);
                let Some(prow) = pivot else {
                    elimination_error = Some(singular_matrix_error(dense_cols, col));
                    break;
                };

                pivot_row[col] = prow;
                row_used[prow] = true;
                pivots_selected += 1;
                if hard_regime && matches!(hard_plan, HardRegimePlan::Markowitz) {
                    markowitz_pivots += 1;
                }

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
                let sparse_cols = sparse_update_columns_if_beneficial(
                    &pivot_buf[..n_cols],
                    n_cols,
                    &mut sparse_cols_buf,
                );

                // Eliminate column in all other rows using block-tiled approach for better cache locality.
                if sparse_cols {
                    let sparse_cols = sparse_cols_buf.as_slice();
                    blocked_elimination_sparse(
                        &mut a,
                        &mut b,
                        n_rows,
                        n_cols,
                        prow,
                        col,
                        &pivot_buf,
                        &pivot_rhs,
                        symbol_size,
                        sparse_cols,
                        &mut gauss_ops,
                    );
                } else {
                    blocked_elimination_dense(
                        &mut a,
                        &mut b,
                        n_rows,
                        n_cols,
                        prow,
                        col,
                        &pivot_buf,
                        &pivot_rhs,
                        symbol_size,
                        &mut gauss_ops,
                    );
                }
            }

            if elimination_error.is_none() {
                if let Some(row) = first_inconsistent_dense_row(&a, n_rows, n_cols, &b) {
                    elimination_error = Some(inconsistent_matrix_error(&dense_rows, row));
                }
            }

            // Record work performed in this attempt, even if we fallback or fail.
            state.stats.pivots_selected += pivots_selected;
            state.stats.markowitz_pivots += markowitz_pivots;
            state.stats.gauss_ops += gauss_ops;

            if let Some(err) = elimination_error {
                if !hard_regime {
                    hard_regime = true;
                    state.stats.hard_regime_activated = true;
                    state.stats.hard_regime_fallbacks += 1;
                    state.stats.hard_regime_conservative_fallback_reason =
                        Some("fallback_after_baseline_failure");
                    // Rebuild matrix BEFORE selecting hard-regime plan so that
                    // density metrics reflect the original matrix, not the
                    // partially-eliminated one.
                    rebuild_dense_matrix_from_equations(
                        &state.equations,
                        &dense_rows,
                        col_to_dense,
                        n_cols,
                        &mut a,
                    )?;
                    restore_dense_rhs(&mut b, &dense_rhs_snapshot, symbol_size);
                    hard_plan = select_hard_regime_plan(n_rows, n_cols, &a);
                    state.stats.hard_regime_branch = Some(hard_plan.label());
                    continue;
                }
                if matches!(hard_plan, HardRegimePlan::BlockSchurLowRank { .. }) {
                    hard_plan = HardRegimePlan::Markowitz;
                    state.stats.hard_regime_fallbacks += 1;
                    state.stats.hard_regime_conservative_fallback_reason =
                        Some("block_schur_failed_to_converge");
                    rebuild_dense_matrix_from_equations(
                        &state.equations,
                        &dense_rows,
                        col_to_dense,
                        n_cols,
                        &mut a,
                    )?;
                    restore_dense_rhs(&mut b, &dense_rhs_snapshot, symbol_size);
                    continue;
                }
                restore_dense_rows_into_state(state, &dense_rows, &dense_rhs_snapshot, symbol_size);
                reactivate_unsolved_columns(state, &unsolved);
                return Err(err);
            }
            break;
        }

        // br-asupersync-cz5b0u — Pre-fix the else-branch silently
        // emitted `vec![0u8; symbol_size]` when `pivot_row[dense_col]
        // >= n_rows`, masking a rank-deficient elimination as a
        // valid all-zeros decode. An attacker crafting a symbol
        // stream where `select_pivot_row` failed to update
        // `pivot_row` for a column (but `elimination_error`
        // remained None due to a defensive code path not firing)
        // would receive a successful decode whose intermediate
        // symbols were attacker-influenced zero blocks. Now any
        // unfilled pivot row surfaces as
        // `DecodeError::SingularMatrix` with the original column id,
        // matching the same error the explicit elimination_error
        // path raises elsewhere.
        for (dense_col, &col) in dense_cols.iter().enumerate() {
            let prow = pivot_row[dense_col];
            if prow < n_rows {
                state.solved[col] = Some(std::mem::take(&mut b[prow]));
            } else {
                return Err(singular_matrix_error(dense_cols, dense_col));
            }
        }

        Ok(())
    }

    /// Phase 2: Inactivation + Gaussian elimination with proof trace capture.
    ///
    /// Like `inactivate_and_solve`, but also records inactivations, pivots,
    /// and row operations to the proof trace.
    #[allow(clippy::too_many_lines)]
    fn inactivate_and_solve_with_proof(
        &self,
        state: &mut DecoderState,
        trace: &mut EliminationTrace,
    ) -> Result<(), DecodeError> {
        // Each decode proof must describe only the current invocation, even if
        // a caller reuses a trace buffer across runs.
        *trace = EliminationTrace::default();
        let symbol_size = self.params.symbol_size;

        // Collect remaining unsolved columns
        let unsolved: Vec<usize> = state
            .column_states
            .iter()
            .enumerate()
            .filter_map(|(col, &state_val)| {
                if state_val == ColumnState::Active && state.solved[col].is_none() {
                    Some(col)
                } else {
                    None
                }
            })
            .collect();

        if unsolved.is_empty() {
            return Ok(());
        }
        state.stats.peeling_fallback_reason = Some("peeling_exhausted_to_dense_core");

        // Collect unused equations
        let unused_eqs: Vec<usize> = state
            .equations
            .iter()
            .enumerate()
            .filter_map(|(i, eq)| if eq.used { None } else { Some(i) })
            .collect();
        let (dense_rows, dropped_zero_rows) = build_dense_core_rows(state, &unused_eqs, &unsolved)?;
        state.stats.dense_core_dropped_rows += dropped_zero_rows;

        // Record the planned inactivation set in the proof trace before any
        // potentially-fallible validation step. The trace must describe the
        // decoder's intent — what it inactivated — even if we fail-closed on
        // RHS width drift without mutating decoder state. Mutations to
        // `state.column_states` updates are deferred until
        // after validation succeeds so callers can roll back deterministically.
        for &col in &unsolved {
            trace.record_inactivation(col);
        }

        validate_dense_core_rhs_widths(state, &dense_rows, symbol_size)?;

        // Mark all remaining unsolved columns as inactive
        for &col in &unsolved {
            state.column_states[col] = ColumnState::Inactive;
            state.stats.inactivated += 1;
        }

        // Reorder dense elimination columns deterministically and reuse cached
        // dense skeleton metadata when signatures match.
        let (dense_factor, cache_observation) =
            self.dense_factor_with_cache(&state.equations, &dense_rows, &unsolved);
        apply_dense_factor_cache_observation(&mut state.stats, cache_observation);
        let dense_cols = &dense_factor.dense_cols;
        let col_to_dense = &dense_factor.col_to_dense;

        // Build dense submatrix for Gaussian elimination
        // Rows = unused equations, Columns = unsolved columns
        let n_rows = dense_rows.len();
        let n_cols = dense_cols.len();
        let inactivation_pressure_permille =
            unsolved.len().saturating_mul(1000) / state.params.l.max(1);
        state.stats.dense_core_rows = n_rows;
        state.stats.dense_core_cols = n_cols;

        let mut b: Vec<Vec<u8>> = Vec::with_capacity(n_rows);

        if n_rows < n_cols {
            reactivate_unsolved_columns(state, &unsolved);
            return Err(singular_matrix_error(&unsolved, n_rows));
        }

        // Build flat row-major dense matrix A and RHS vector b.
        // Move (take) RHS data from state instead of cloning to avoid O(n_rows * symbol_size)
        // heap allocation in this hot path.
        let total_cells = match n_rows.checked_mul(n_cols) {
            Some(total_cells) => total_cells,
            None => {
                let err = DecodeError::InsufficientSymbols {
                    received: n_rows,
                    required: n_cols,
                };
                reactivate_unsolved_columns(state, &unsolved);
                return Err(err);
            }
        };
        let mut a = vec![Gf256::ZERO; total_cells];
        let mut dense_nonzeros = 0usize;
        let mut dense_col_support = vec![0usize; n_cols];

        for (row, &eq_idx) in dense_rows.iter().enumerate() {
            let row_off = row * n_cols;
            for &(col, coef) in &state.equations[eq_idx].terms {
                if let Some(dense_col) = dense_col_index(col_to_dense, col) {
                    a[row_off + dense_col] = coef;
                    if !coef.is_zero() {
                        dense_nonzeros += 1;
                        dense_col_support[dense_col] += 1;
                    }
                }
            }
            b.push(std::mem::take(&mut state.rhs[eq_idx]));
        }
        let unsupported_cols = dense_col_support
            .iter()
            .filter(|&&support| support == 0)
            .count();
        let dense_rhs_snapshot = snapshot_dense_rhs(&b, symbol_size)?;

        trace.set_strategy(InactivationStrategy::AllAtOnce);
        let decision = choose_runtime_decoder_policy(
            n_rows,
            n_cols,
            dense_nonzeros,
            unsupported_cols,
            inactivation_pressure_permille,
        );
        apply_policy_decision_to_stats(&mut state.stats, &decision);
        let mut hard_regime = !matches!(decision.mode, DecoderPolicyMode::ConservativeBaseline);
        let mut hard_plan = match decision.mode {
            DecoderPolicyMode::ConservativeBaseline | DecoderPolicyMode::HighSupportFirst => {
                HardRegimePlan::Markowitz
            }
            DecoderPolicyMode::BlockSchurLowRank => select_hard_regime_plan(n_rows, n_cols, &a),
        };
        if hard_regime {
            state.stats.hard_regime_activated = true;
            state.stats.hard_regime_branch = Some(hard_plan.label());
            trace.record_strategy_transition(
                InactivationStrategy::AllAtOnce,
                hard_plan.strategy(),
                "dense_or_near_square",
            );
        } else if decision.reason == "policy_budget_exhausted_conservative" {
            state.stats.hard_regime_conservative_fallback_reason = Some(decision.reason);
        }

        let mut pivot_row = vec![usize::MAX; n_cols];
        loop {
            pivot_row.fill(usize::MAX);
            let mut row_used = vec![false; n_rows];
            let mut pivot_buf = vec![Gf256::ZERO; n_cols];
            let mut pivot_rhs = vec![0u8; symbol_size];
            let mut sparse_cols_buf = Vec::with_capacity(sparse_update_column_capacity(n_cols));
            let mut gauss_ops = 0usize;
            let mut pivots_selected = 0usize;
            let mut markowitz_pivots = 0usize;
            let mut elimination_error = None;

            for col in 0..n_cols {
                let pivot =
                    select_pivot_row(&a, n_rows, n_cols, col, &row_used, hard_regime, hard_plan);
                let Some(prow) = pivot else {
                    elimination_error = Some(singular_matrix_error(dense_cols, col));
                    break;
                };

                pivot_row[col] = prow;
                row_used[prow] = true;
                pivots_selected += 1;
                if hard_regime && matches!(hard_plan, HardRegimePlan::Markowitz) {
                    markowitz_pivots += 1;
                }
                // Record pivot in proof trace (use original column index)
                trace.record_pivot(dense_cols[col], prow);

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
                let sparse_cols = sparse_update_columns_if_beneficial(
                    &pivot_buf[..n_cols],
                    n_cols,
                    &mut sparse_cols_buf,
                );

                // Eliminate column in all other rows.
                if sparse_cols {
                    let sparse_cols = sparse_cols_buf.as_slice();
                    for (row, rhs) in b.iter_mut().enumerate().take(n_rows) {
                        if row == prow {
                            continue;
                        }
                        let row_off = row * n_cols;
                        let factor = a[row_off + col];
                        if factor.is_zero() {
                            continue;
                        }
                        for &c in sparse_cols {
                            a[row_off + c] += factor * pivot_buf[c];
                        }
                        gf256_addmul_slice(rhs, &pivot_rhs[..symbol_size], factor);
                        gauss_ops += 1;
                        // Record row operation in proof trace
                        trace.record_row_op();
                    }
                } else {
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
                        gauss_ops += 1;
                        // Record row operation in proof trace
                        trace.record_row_op();
                    }
                }
            }

            if elimination_error.is_none() {
                if let Some(row) = first_inconsistent_dense_row(&a, n_rows, n_cols, &b) {
                    elimination_error = Some(inconsistent_matrix_error(&dense_rows, row));
                }
            }

            // Record work performed in this attempt, even if we fallback or fail.
            state.stats.pivots_selected += pivots_selected;
            state.stats.markowitz_pivots += markowitz_pivots;
            state.stats.gauss_ops += gauss_ops;

            if let Some(err) = elimination_error {
                if !hard_regime {
                    hard_regime = true;
                    state.stats.hard_regime_activated = true;
                    state.stats.hard_regime_fallbacks += 1;
                    state.stats.hard_regime_conservative_fallback_reason =
                        Some("fallback_after_baseline_failure");
                    // Rebuild matrix BEFORE selecting hard-regime plan so that
                    // density metrics reflect the original matrix, not the
                    // partially-eliminated one.
                    rebuild_dense_matrix_from_equations(
                        &state.equations,
                        &dense_rows,
                        col_to_dense,
                        n_cols,
                        &mut a,
                    )?;
                    restore_dense_rhs(&mut b, &dense_rhs_snapshot, symbol_size);
                    hard_plan = select_hard_regime_plan(n_rows, n_cols, &a);
                    state.stats.hard_regime_branch = Some(hard_plan.label());
                    trace.record_strategy_transition(
                        InactivationStrategy::AllAtOnce,
                        hard_plan.strategy(),
                        "fallback_after_baseline_failure",
                    );
                    trace.pivots = 0;
                    trace.pivot_events.clear();
                    trace.row_ops = 0;
                    trace.pivot_events_truncated = false;
                    continue;
                }
                if matches!(hard_plan, HardRegimePlan::BlockSchurLowRank { .. }) {
                    hard_plan = HardRegimePlan::Markowitz;
                    state.stats.hard_regime_fallbacks += 1;
                    state.stats.hard_regime_conservative_fallback_reason =
                        Some("block_schur_failed_to_converge");
                    trace.record_strategy_transition(
                        InactivationStrategy::BlockSchurLowRank,
                        InactivationStrategy::HighSupportFirst,
                        "block_schur_failed_to_converge",
                    );
                    trace.pivots = 0;
                    trace.pivot_events.clear();
                    trace.row_ops = 0;
                    trace.pivot_events_truncated = false;
                    rebuild_dense_matrix_from_equations(
                        &state.equations,
                        &dense_rows,
                        col_to_dense,
                        n_cols,
                        &mut a,
                    )?;
                    restore_dense_rhs(&mut b, &dense_rhs_snapshot, symbol_size);
                    continue;
                }
                restore_dense_rows_into_state(state, &dense_rows, &dense_rhs_snapshot, symbol_size);
                reactivate_unsolved_columns(state, &unsolved);
                return Err(err);
            }
            break;
        }

        // br-asupersync-cz5b0u — Pre-fix the else-branch silently
        // emitted `vec![0u8; symbol_size]` when `pivot_row[dense_col]
        // >= n_rows`, masking a rank-deficient elimination as a
        // valid all-zeros decode. An attacker crafting a symbol
        // stream where `select_pivot_row` failed to update
        // `pivot_row` for a column (but `elimination_error`
        // remained None due to a defensive code path not firing)
        // would receive a successful decode whose intermediate
        // symbols were attacker-influenced zero blocks. Now any
        // unfilled pivot row surfaces as
        // `DecodeError::SingularMatrix` with the original column id,
        // matching the same error the explicit elimination_error
        // path raises elsewhere.
        for (dense_col, &col) in dense_cols.iter().enumerate() {
            let prow = pivot_row[dense_col];
            if prow < n_rows {
                state.solved[col] = Some(std::mem::take(&mut b[prow]));
            } else {
                return Err(singular_matrix_error(dense_cols, dense_col));
            }
        }

        Ok(())
    }

    /// Generate the RFC 6330 tuple-derived equation (columns + coefficients) for a repair symbol.
    ///
    /// This must stay in parity with `SystematicEncoder::repair_symbol` so that
    /// decoder row construction exactly matches encoder repair bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if the ESI causes overflow in the repair ISI calculation.
    pub fn repair_equation(&self, esi: u32) -> Result<(Vec<usize>, Vec<Gf256>), SystematicError> {
        self.params.rfc_repair_equation(esi)
    }

    /// Generate the equation (columns + coefficients) using RFC 6330 tuple rules.
    ///
    /// This method computes tuple parameters from RFC 6330 Section 5.3.5.4 and
    /// expands them into intermediate symbol indices using Section 5.3.5.3.
    ///
    /// This is kept as an explicit alias used by RFC conformance tests.
    ///
    /// Returns `None` if the ESI causes overflow in the repair ISI calculation or if
    /// the systematic parameters are invalid for the given ESI.
    #[must_use]
    pub fn repair_equation_rfc6330(&self, esi: u32) -> Option<(Vec<usize>, Vec<Gf256>)> {
        self.repair_equation(esi).ok()
    }

    fn received_symbol_equation(&self, sym: &ReceivedSymbol) -> Equation {
        if sym.is_source {
            let (columns, coefficients) = self.source_equation(sym.esi);
            Equation::new(columns, coefficients)
        } else {
            Equation::new(sym.columns.clone(), sym.coefficients.clone())
        }
    }

    fn reconstruct_source_symbols(
        &self,
        intermediate: &[Option<Vec<u8>>],
    ) -> Result<Vec<Vec<u8>>, DecodeError> {
        let mut source = Vec::with_capacity(self.params.k);
        for esi in 0..self.params.k {
            let esi_u32 =
                u32::try_from(esi).expect("decoder params guarantee source ESI fits in u32");
            let (columns, coefficients) = self.source_equation(esi_u32);
            let mut symbol = vec![0u8; self.params.symbol_size];
            for (&column, &coefficient) in columns.iter().zip(coefficients.iter()) {
                let intermediate_symbol =
                    require_intermediate_symbol(intermediate, column, self.params.symbol_size)?;
                gf256_addmul_slice(&mut symbol, intermediate_symbol, coefficient);
            }
            source.push(symbol);
        }
        Ok(source)
    }

    fn materialize_intermediate_symbols(
        &self,
        intermediate: Vec<Option<Vec<u8>>>,
    ) -> Result<Vec<Vec<u8>>, DecodeError> {
        let symbol_size = self.params.symbol_size;
        intermediate
            .into_iter()
            .map(|opt| match opt {
                Some(symbol) if symbol.len() == symbol_size => Ok(symbol),
                Some(symbol) => Err(DecodeError::SymbolSizeMismatch {
                    expected: symbol_size,
                    actual: symbol.len(),
                }),
                None => Ok(vec![0u8; symbol_size]),
            })
            .collect()
    }

    fn systematic_equation(&self, esi: u32) -> (Vec<usize>, Vec<Gf256>) {
        assert!(
            (esi as usize) < self.params.k_prime,
            "systematic ESI must be < K'"
        );
        let columns = repair_indices_for_esi(self.params.j, self.params.w, self.params.p, esi);
        let coefficients = vec![Gf256::ONE; columns.len()];
        (columns, coefficients)
    }

    /// Generate equations for all K source symbols.
    ///
    /// RFC 6330 systematic source symbols are encoded symbol IDs `0..K-1`;
    /// each source row is the corresponding tuple expansion over intermediate
    /// symbols.
    #[must_use]
    pub fn all_source_equations(&self) -> Vec<(Vec<usize>, Vec<Gf256>)> {
        (0..self.params.k)
            .map(|i| self.source_equation(u32::try_from(i).expect("source ESI must fit in u32")))
            .collect()
    }

    /// Get the equation for a specific source symbol ESI.
    ///
    /// In systematic encoding, source symbol `esi` maps through the RFC 6330
    /// tuple expansion for encoded symbol ID `esi`.
    #[must_use]
    pub fn source_equation(&self, esi: u32) -> (Vec<usize>, Vec<Gf256>) {
        assert!((esi as usize) < self.params.k, "source ESI must be < K");
        self.systematic_equation(esi)
    }

    fn validate_source_symbol_equation(&self, sym: &ReceivedSymbol) -> Result<(), DecodeError> {
        if !sym.is_source {
            return Ok(());
        }

        let k = self.params.k;
        let esi = sym.esi as usize;
        if esi >= k {
            return Err(DecodeError::SourceEsiOutOfRange {
                esi: sym.esi,
                max_valid: k,
            });
        }

        let (expected_cols, expected_coefs) = self.source_equation(sym.esi);
        let derive_canonical_from_esi = sym.columns.is_empty() && sym.coefficients.is_empty();
        let canonical_equation = sym.columns == expected_cols && sym.coefficients == expected_coefs;
        if !derive_canonical_from_esi && !canonical_equation {
            return Err(DecodeError::InvalidSourceSymbolEquation {
                esi: sym.esi,
                expected_column: esi,
            });
        }

        Ok(())
    }

    fn validate_rank_input(&self, symbols: &[ReceivedSymbol]) -> Result<(), DecodeError> {
        let l = self.params.l;
        let symbol_size = self.params.symbol_size;
        let mut seen_source_payloads = HashMap::with_capacity(self.params.k.min(symbols.len()));
        let mut seen_equation_payloads = SeenEquationPayloads::with_capacity(symbols.len());

        for sym in symbols {
            if sym.data.len() != symbol_size {
                return Err(DecodeError::SymbolSizeMismatch {
                    expected: symbol_size,
                    actual: sym.data.len(),
                });
            }
            if sym.columns.len() != sym.coefficients.len() {
                return Err(DecodeError::SymbolEquationArityMismatch {
                    esi: sym.esi,
                    columns: sym.columns.len(),
                    coefficients: sym.coefficients.len(),
                });
            }
            self.validate_source_symbol_equation(sym)?;
            self.validate_symbol_payload_consistency(
                sym,
                &mut seen_source_payloads,
                &mut seen_equation_payloads,
            )?;
            for &column in &sym.columns {
                if column >= l {
                    return Err(DecodeError::ColumnIndexOutOfRange {
                        esi: sym.esi,
                        column,
                        max_valid: l,
                    });
                }
            }
        }

        Ok(())
    }
}

fn first_mismatch_byte(expected: &[u8], actual: &[u8]) -> Option<usize> {
    expected
        .iter()
        .zip(actual.iter())
        .position(|(expected, actual)| expected != actual)
}

fn require_intermediate_symbol(
    intermediate: &[Option<Vec<u8>>],
    column: usize,
    symbol_size: usize,
) -> Result<&[u8], DecodeError> {
    let Some(symbol) = intermediate.get(column).and_then(Option::as_ref) else {
        return Err(DecodeError::SingularMatrix { row: column });
    };
    if symbol.len() != symbol_size {
        return Err(DecodeError::SymbolSizeMismatch {
            expected: symbol_size,
            actual: symbol.len(),
        });
    }
    Ok(symbol)
}

#[cfg(test)]
fn equation_rank(equations: &[Equation], column_count: usize) -> usize {
    equation_rank_profile(equations, column_count).rank
}

fn equation_rank_profile(equations: &[Equation], column_count: usize) -> GaussianRankProfile {
    let mut dense_rows = Vec::with_capacity(equations.len());
    for equation in equations {
        let mut row = vec![0u8; column_count];
        for &(col_idx, coefficient) in &equation.terms {
            row[col_idx] ^= coefficient.raw();
        }
        dense_rows.push(row);
    }
    let dense_refs: Vec<&[u8]> = dense_rows.iter().map(Vec::as_slice).collect();

    coefficient_rank_profile(&dense_refs, column_count)
}

fn rebuild_dense_matrix_from_equations(
    equations: &[Equation],
    dense_rows: &[usize],
    col_to_dense: &DenseColIndexMap,
    n_cols: usize,
    a: &mut [Gf256],
) -> Result<(), DecodeError> {
    a.fill(Gf256::ZERO);
    for (row, &eq_idx) in dense_rows.iter().enumerate() {
        // br-asupersync-lw16f6 — Bounds-check `row_off + dense_col`
        // against `a.len()` before the write. Pre-fix the offset
        // arithmetic was unguarded and a malformed schedule that
        // produced a `row >= dense_rows.len()` (off-by-one) OR a
        // `dense_col >= n_cols` (col_to_dense corrupt) would index
        // out of bounds — silent OOB-write in release, panic in
        // debug. The dense matrix is sized at decoder.rs:1971 via
        // `checked_mul` so the buffer is correctly sized for
        // legitimate inputs; this guard makes the loop fail closed
        // on malformed inputs that bypass the upstream sizing.
        let row_off = row
            .checked_mul(n_cols)
            .ok_or(DecodeError::SingularMatrix { row: eq_idx })?;
        for &(col, coef) in &equations[eq_idx].terms {
            if let Some(dense_col) = dense_col_index(col_to_dense, col) {
                let off = row_off
                    .checked_add(dense_col)
                    .filter(|&o| o < a.len())
                    .ok_or(DecodeError::SingularMatrix { row: eq_idx })?;
                a[off] = coef;
            }
        }
    }
    Ok(())
}

fn snapshot_dense_rhs(rows: &[Vec<u8>], symbol_size: usize) -> Result<Vec<u8>, DecodeError> {
    // br-asupersync-n47w54 — Pre-fix used `saturating_mul` for the
    // total snapshot size. saturation is the wrong shape for an
    // alloc: if `rows.len() * symbol_size` saturates to usize::MAX,
    // the alloc either panics in `vec!` with capacity-overflow
    // anyway, OR (more dangerously) the loop below uses unsaturated
    // arithmetic for `off = row_idx * symbol_size` and indexes
    // PAST the saturated buffer end. Switching to `checked_mul +
    // proper error handling makes the overflow fail gracefully.
    let total = rows
        .len()
        .checked_mul(symbol_size)
        .ok_or(DecodeError::SingularMatrix { row: rows.len() })?;
    let mut snapshot = vec![0u8; total];
    for (row_idx, row) in rows.iter().enumerate() {
        debug_assert_eq!(row.len(), symbol_size);
        let off = row_idx * symbol_size;
        snapshot[off..off + symbol_size].copy_from_slice(row);
    }
    Ok(snapshot)
}

fn restore_dense_rhs(rows: &mut [Vec<u8>], snapshot: &[u8], symbol_size: usize) {
    debug_assert_eq!(snapshot.len(), rows.len().saturating_mul(symbol_size));
    for (row_idx, row) in rows.iter_mut().enumerate() {
        debug_assert_eq!(row.len(), symbol_size);
        let off = row_idx * symbol_size;
        row.copy_from_slice(&snapshot[off..off + symbol_size]);
    }
}

fn restore_dense_rows_into_state(
    state: &mut DecoderState,
    dense_rows: &[usize],
    snapshot: &[u8],
    symbol_size: usize,
) {
    debug_assert_eq!(snapshot.len(), dense_rows.len().saturating_mul(symbol_size));
    for (row_idx, &eq_idx) in dense_rows.iter().enumerate() {
        let off = row_idx * symbol_size;
        state.rhs[eq_idx] = snapshot[off..off + symbol_size].to_vec();
    }
}

fn reactivate_unsolved_columns(state: &mut DecoderState, unsolved: &[usize]) {
    for &col in unsolved {
        state.column_states[col] = ColumnState::Active;
    }
}

// ============================================================================
// Block-tiled Gaussian elimination for better cache locality
// ============================================================================

/// Block size for cache-friendly matrix operations (fits in L1 cache).
/// For GF(256) elements (1 byte each), 256x256 = 64KB fits comfortably in L1.
const BLOCK_SIZE: usize = 256;

/// Block-tiled elimination for sparse column updates.
///
/// Processes matrix elimination in cache-friendly blocks to improve memory
/// locality and reduce bandwidth pressure. This provides 2-4x speedup for
/// large dense matrices (K=10000+) by better utilizing CPU cache hierarchy.
fn blocked_elimination_sparse(
    a: &mut [Gf256],
    b: &mut [Vec<u8>],
    n_rows: usize,
    n_cols: usize,
    prow: usize,
    col: usize,
    pivot_buf: &[Gf256],
    pivot_rhs: &[u8],
    symbol_size: usize,
    sparse_cols: &[usize],
    gauss_ops: &mut usize,
) {
    // Process rows in blocks for better cache locality
    let block_size = BLOCK_SIZE.min(n_rows).max(1);

    for row_start in (0..n_rows).step_by(block_size) {
        let row_end = (row_start + block_size).min(n_rows);

        #[allow(clippy::needless_range_loop)] // row index needed for matrix offset calculation
        for row in row_start..row_end {
            if row == prow {
                continue;
            }

            let row_off = row * n_cols;
            let factor = a[row_off + col];
            if factor.is_zero() {
                continue;
            }

            // Update sparse columns in cache-friendly order
            for &c in sparse_cols {
                a[row_off + c] += factor * pivot_buf[c];
            }

            // SIMD-optimized RHS update (already optimized in gf256_addmul_slice)
            gf256_addmul_slice(&mut b[row], &pivot_rhs[..symbol_size], factor);
            *gauss_ops += 1;
        }
    }
}

/// Block-tiled elimination for dense column updates.
///
/// Uses blocking to improve cache locality when all columns need updates.
/// Processes both row and column dimensions in blocks to maximize reuse.
fn blocked_elimination_dense(
    a: &mut [Gf256],
    b: &mut [Vec<u8>],
    n_rows: usize,
    n_cols: usize,
    prow: usize,
    col: usize,
    pivot_buf: &[Gf256],
    pivot_rhs: &[u8],
    symbol_size: usize,
    gauss_ops: &mut usize,
) {
    // Use smaller block size for dense updates to fit pivot_buf in cache
    let row_block_size = BLOCK_SIZE.min(n_rows).max(1);
    let col_block_size = (BLOCK_SIZE / 4).min(n_cols).max(1); // Smaller for better pivot_buf reuse

    // Process in row blocks
    for row_start in (0..n_rows).step_by(row_block_size) {
        let row_end = (row_start + row_block_size).min(n_rows);

        // Process each row block with column blocking
        #[allow(clippy::needless_range_loop)] // row index needed for matrix offset calculation
        for row in row_start..row_end {
            if row == prow {
                continue;
            }

            let row_off = row * n_cols;
            let factor = a[row_off + col];
            if factor.is_zero() {
                continue;
            }

            // Process columns in blocks for better cache utilization
            for col_start in (0..n_cols).step_by(col_block_size) {
                let col_end = (col_start + col_block_size).min(n_cols);

                for c in col_start..col_end {
                    a[row_off + c] += factor * pivot_buf[c];
                }
            }

            // RHS update (already SIMD-optimized)
            gf256_addmul_slice(&mut b[row], &pivot_rhs[..symbol_size], factor);
            *gauss_ops += 1;
        }
    }
}

// ============================================================================
// Helper: build ReceivedSymbol from raw data
// ============================================================================

impl ReceivedSymbol {
    /// Create a source symbol (ESI < K).
    /// The decoder will derive proper intermediate symbol indices from the ESI.
    #[must_use]
    pub fn source(esi: u32, data: Vec<u8>) -> Self {
        Self {
            esi,
            is_source: true,
            columns: vec![], // Empty - decoder derives from ESI using RFC equations
            coefficients: vec![], // Empty - decoder derives from ESI using RFC equations
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
include!("decoder_tests.rs");
