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
use crate::raptorq::proof::{
    DecodeConfig, DecodeProof, EliminationTrace, FailureReason, InactivationStrategy, PeelingTrace,
    ReceivedSummary,
};
use crate::raptorq::systematic::{ConstraintMatrix, SystematicParams};
use crate::types::ObjectId;

use std::collections::{BTreeSet, VecDeque};
use std::hash::{Hash, Hasher};

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
    pub const fn failure_class(&self) -> DecodeFailureClass {
        match self {
            Self::InsufficientSymbols { .. } | Self::SingularMatrix { .. } => {
                DecodeFailureClass::Recoverable
            }
            Self::SymbolSizeMismatch { .. }
            | Self::SymbolEquationArityMismatch { .. }
            | Self::ColumnIndexOutOfRange { .. }
            | Self::CorruptDecodedOutput { .. } => DecodeFailureClass::Unrecoverable,
        }
    }

    /// True when this failure can be retried by supplying additional symbols.
    #[must_use]
    pub const fn is_recoverable(&self) -> bool {
        matches!(self.failure_class(), DecodeFailureClass::Recoverable)
    }

    /// True when this failure indicates malformed input or corruption.
    #[must_use]
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
    /// F6 regime-shift detector: current CUSUM score (signed, bounded).
    pub regime_score: i64,
    /// F6 regime-shift detector: current regime state label.
    pub regime_state: Option<&'static str>,
    /// F6 regime-shift detector: number of retuning events applied.
    pub regime_retune_count: usize,
    /// F6 regime-shift detector: number of rollbacks to conservative defaults.
    pub regime_rollback_count: usize,
    /// F6 regime-shift detector: current window occupancy.
    pub regime_window_len: usize,
    /// F6 regime-shift detector: current density bias delta (permille adjustment).
    pub regime_delta_density_bias: i32,
    /// F6 regime-shift detector: current pressure bias delta (permille adjustment).
    pub regime_delta_pressure_bias: i32,
    /// F6 regime-shift detector: replay pointer for retuning forensics.
    pub regime_replay_ref: Option<&'static str>,
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

const DENSE_FACTOR_CACHE_CAPACITY: usize = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DenseFactorCacheResult {
    Hit,
    MissInserted,
    MissEvicted,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum DenseFactorCacheLookup {
    Hit(DenseFactorArtifact),
    MissNoEntry,
    MissFingerprintCollision,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DenseFactorArtifact {
    dense_cols: Vec<usize>,
    col_to_dense: Vec<usize>,
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
struct DenseFactorSignature {
    fingerprint: u64,
    unsolved: Vec<usize>,
    row_terms: Vec<Vec<(usize, u8)>>,
}

impl DenseFactorSignature {
    fn from_equations(equations: &[Equation], dense_rows: &[usize], unsolved: &[usize]) -> Self {
        let mut unsolved_mask = Vec::new();
        if let Some(max_col) = unsolved.iter().copied().max() {
            unsolved_mask = vec![false; max_col.saturating_add(1)];
            for &col in unsolved {
                unsolved_mask[col] = true;
            }
        }

        let row_terms: Vec<Vec<(usize, u8)>> = dense_rows
            .iter()
            .map(|&eq_idx| {
                equations[eq_idx]
                    .terms
                    .iter()
                    .filter_map(|(col, coef)| {
                        let is_unsolved = unsolved_mask.get(*col).copied().unwrap_or(false);
                        if !is_unsolved || coef.is_zero() {
                            return None;
                        }
                        Some((*col, coef.raw()))
                    })
                    .collect()
            })
            .collect();

        let mut hasher = crate::util::DetHasher::default();
        unsolved.hash(&mut hasher);
        row_terms.hash(&mut hasher);
        let fingerprint = hasher.finish();

        Self {
            fingerprint,
            unsolved: unsolved.to_vec(),
            row_terms,
        }
    }
}

#[derive(Debug, Clone)]
struct DenseFactorCacheEntry {
    signature: DenseFactorSignature,
    artifact: DenseFactorArtifact,
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
        artifact: DenseFactorArtifact,
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

    fn len(&self) -> usize {
        self.entries.len()
    }
}

// ============================================================================
// F6: Regime-shift detector
// ============================================================================

/// Maximum number of observations in the regime detector window.
const REGIME_WINDOW_CAPACITY: usize = 32;

/// CUSUM threshold for declaring a regime shift (in permille-scaled score units).
/// A score that exceeds this indicates the workload has drifted far enough from
/// baseline that retuning should be considered.
const REGIME_SHIFT_THRESHOLD: i64 = 500;

/// Maximum absolute adjustment to any loss-model bias term (permille).
/// Retuning deltas are clamped to [-cap, +cap] to satisfy the "no unbounded
/// online learning" safety constraint.
const REGIME_MAX_RETUNE_DELTA: i32 = 200;

/// Number of consecutive oscillations (shift→rollback→shift) before the detector
/// permanently locks to conservative defaults for this decoder instance.
const REGIME_ROLLBACK_OSCILLATION_LIMIT: usize = 3;

/// Replay pointer for F6 regime-shift retuning events.
const REGIME_REPLAY_REF: &str = "replay:rq-track-f-regime-shift-v1";

/// Labels for the regime detector state machine.
const REGIME_STATE_STABLE: &str = "stable";
const REGIME_STATE_SHIFTING: &str = "shifting";
const REGIME_STATE_RETUNED: &str = "retuned";
const REGIME_STATE_ROLLBACK: &str = "rollback";
const REGIME_STATE_LOCKED: &str = "locked_conservative";

/// A single observation fed to the regime detector after each decode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RegimeObservation {
    /// Policy features observed during the decode.
    features: DecoderPolicyFeatures,
    /// Whether the decode succeeded.
    decode_success: bool,
    /// The policy mode that was selected.
    policy_mode: DecoderPolicyMode,
}

/// Bounded retuning deltas applied to the loss-model bias terms.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[allow(clippy::struct_field_names)]
struct RetuningDeltas {
    /// Adjustment to the conservative baseline intercept (added to 400).
    baseline_intercept_delta: i32,
    /// Adjustment to the density coefficient for baseline (multiplied by 3 + delta).
    density_bias_delta: i32,
    /// Adjustment to the inactivation pressure coefficient (multiplied by 2 + delta).
    pressure_bias_delta: i32,
}

impl RetuningDeltas {
    /// Clamp all deltas to the allowed cap range.
    fn clamped(self) -> Self {
        Self {
            baseline_intercept_delta: self
                .baseline_intercept_delta
                .clamp(-REGIME_MAX_RETUNE_DELTA, REGIME_MAX_RETUNE_DELTA),
            density_bias_delta: self
                .density_bias_delta
                .clamp(-REGIME_MAX_RETUNE_DELTA, REGIME_MAX_RETUNE_DELTA),
            pressure_bias_delta: self
                .pressure_bias_delta
                .clamp(-REGIME_MAX_RETUNE_DELTA, REGIME_MAX_RETUNE_DELTA),
        }
    }

    /// True when all deltas are zero (conservative defaults).
    fn is_zero(&self) -> bool {
        self.baseline_intercept_delta == 0
            && self.density_bias_delta == 0
            && self.pressure_bias_delta == 0
    }
}

/// The regime detector's internal state machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RegimePhase {
    /// Accumulating baseline statistics, no retuning active.
    Stable,
    /// A shift has been detected but not yet acted upon (needs confirmation).
    Shifting,
    /// Retuning deltas are active.
    Retuned,
    /// Rolled back to conservative defaults after instability.
    Rollback,
    /// Permanently locked to conservative defaults (oscillation limit hit).
    LockedConservative,
}

impl RegimePhase {
    const fn label(self) -> &'static str {
        match self {
            Self::Stable => REGIME_STATE_STABLE,
            Self::Shifting => REGIME_STATE_SHIFTING,
            Self::Retuned => REGIME_STATE_RETUNED,
            Self::Rollback => REGIME_STATE_ROLLBACK,
            Self::LockedConservative => REGIME_STATE_LOCKED,
        }
    }
}

/// Bounded windowed regime-shift detector.
///
/// Maintains a fixed-size ring buffer of recent policy feature observations.
/// Uses a deterministic CUSUM (cumulative sum control chart) to detect when
/// the workload regime has shifted significantly. On shift detection, computes
/// bounded retuning deltas to adjust the policy engine's loss-model biases.
///
/// Safety invariants:
/// - Window is bounded to `REGIME_WINDOW_CAPACITY` entries.
/// - Retuning deltas never exceed `REGIME_MAX_RETUNE_DELTA` in any dimension.
/// - After `REGIME_ROLLBACK_OSCILLATION_LIMIT` oscillations, locks to conservative.
/// - Deterministic for fixed input sequences (no floating point, no randomness).
#[derive(Debug)]
struct RegimeDetector {
    /// Ring buffer of recent observations. Front = oldest, back = newest.
    window: VecDeque<RegimeObservation>,
    /// Running sum of density permille values in the window.
    density_sum: i64,
    /// Running sum of inactivation pressure permille values in the window.
    pressure_sum: i64,
    /// Baseline density mean (permille), established from first REGIME_WINDOW_CAPACITY observations.
    baseline_density: i64,
    /// Baseline pressure mean (permille), established similarly.
    baseline_pressure: i64,
    /// Whether the baseline has been established (window filled at least once).
    baseline_established: bool,
    /// Current CUSUM score for density drift.
    cusum_density: i64,
    /// Current CUSUM score for pressure drift.
    cusum_pressure: i64,
    /// Current phase of the detector state machine.
    phase: RegimePhase,
    /// Active retuning deltas (zero when not retuned).
    deltas: RetuningDeltas,
    /// Total number of retuning events applied.
    retune_count: usize,
    /// Total number of rollbacks performed.
    rollback_count: usize,
    /// Consecutive oscillation count (shift→rollback→shift cycles).
    oscillation_count: usize,
}

impl Default for RegimeDetector {
    fn default() -> Self {
        Self {
            window: VecDeque::with_capacity(REGIME_WINDOW_CAPACITY),
            density_sum: 0,
            pressure_sum: 0,
            baseline_density: 0,
            baseline_pressure: 0,
            baseline_established: false,
            cusum_density: 0,
            cusum_pressure: 0,
            phase: RegimePhase::Stable,
            deltas: RetuningDeltas::default(),
            retune_count: 0,
            rollback_count: 0,
            oscillation_count: 0,
        }
    }
}

impl RegimeDetector {
    /// Record a new observation and update the detector state.
    ///
    /// Returns the current retuning deltas (may be zero if stable or locked).
    #[allow(clippy::cast_possible_wrap)] // permille values (<=1000) and window len (<=32) never wrap
    fn observe(&mut self, obs: RegimeObservation) -> RetuningDeltas {
        // Permanently locked — no further adaptation.
        if self.phase == RegimePhase::LockedConservative {
            return RetuningDeltas::default();
        }

        // Maintain bounded window.
        let density_val = obs.features.density_permille as i64;
        let pressure_val = obs.features.inactivation_pressure_permille as i64;

        if self.window.len() >= REGIME_WINDOW_CAPACITY {
            if let Some(evicted) = self.window.pop_front() {
                self.density_sum -= evicted.features.density_permille as i64;
                self.pressure_sum -= evicted.features.inactivation_pressure_permille as i64;
            }
        }
        self.window.push_back(obs);
        self.density_sum += density_val;
        self.pressure_sum += pressure_val;

        let window_len = self.window.len() as i64;

        // Establish baseline once the window fills for the first time.
        if !self.baseline_established {
            if self.window.len() >= REGIME_WINDOW_CAPACITY {
                self.baseline_density = self.density_sum / window_len;
                self.baseline_pressure = self.pressure_sum / window_len;
                self.baseline_established = true;
            }
            return self.deltas;
        }

        // Compute current window means.
        let current_density_mean = self.density_sum / window_len;
        let current_pressure_mean = self.pressure_sum / window_len;

        // CUSUM update: accumulate drift from baseline.
        // Use two-sided CUSUM (absolute deviation) for simplicity and determinism.
        let density_deviation = (current_density_mean - self.baseline_density).abs();
        let pressure_deviation = (current_pressure_mean - self.baseline_pressure).abs();

        // CUSUM with reset-to-zero when below zero (one-sided positive CUSUM).
        self.cusum_density = (self.cusum_density + density_deviation - 50).max(0);
        self.cusum_pressure = (self.cusum_pressure + pressure_deviation - 30).max(0);

        let combined_score = self.cusum_density + self.cusum_pressure;

        match self.phase {
            RegimePhase::Stable => {
                if combined_score >= REGIME_SHIFT_THRESHOLD {
                    self.phase = RegimePhase::Shifting;
                }
            }
            RegimePhase::Shifting => {
                // Confirm the shift: if score is still above threshold, retune.
                if combined_score >= REGIME_SHIFT_THRESHOLD {
                    self.apply_retuning(current_density_mean, current_pressure_mean);
                } else {
                    // Transient spike, return to stable.
                    self.phase = RegimePhase::Stable;
                    self.cusum_density = 0;
                    self.cusum_pressure = 0;
                }
            }
            RegimePhase::Retuned => {
                // Monitor for instability: if a retuned decode fails, roll back.
                if !obs.decode_success {
                    self.rollback();
                }
                // Also rollback if the regime shifted again (score back above threshold
                // relative to the *new* baseline would mean the retuning didn't help).
                if combined_score >= REGIME_SHIFT_THRESHOLD * 2 {
                    self.rollback();
                }
            }
            RegimePhase::Rollback => {
                // After rollback, re-establish baseline from scratch.
                self.baseline_established = false;
                self.cusum_density = 0;
                self.cusum_pressure = 0;
                self.phase = RegimePhase::Stable;
            }
            RegimePhase::LockedConservative => {
                // Unreachable due to early return above.
            }
        }

        self.deltas
    }

    /// Compute and apply bounded retuning deltas based on the observed drift.
    fn apply_retuning(&mut self, current_density_mean: i64, current_pressure_mean: i64) {
        let density_drift = current_density_mean - self.baseline_density;
        let pressure_drift = current_pressure_mean - self.baseline_pressure;

        // Compute deltas: if density increased, lower baseline intercept to make
        // aggressive modes more accessible; if pressure increased, adjust pressure
        // sensitivity.
        let raw_deltas = RetuningDeltas {
            baseline_intercept_delta: -(density_drift as i32 / 5),
            density_bias_delta: -(density_drift as i32 / 10),
            pressure_bias_delta: -(pressure_drift as i32 / 10),
        };

        self.deltas = raw_deltas.clamped();
        self.phase = RegimePhase::Retuned;
        self.retune_count += 1;

        // Update baseline to current means to prevent repeated re-triggering.
        self.baseline_density = current_density_mean;
        self.baseline_pressure = current_pressure_mean;

        // Reset CUSUM accumulators after successful retuning.
        self.cusum_density = 0;
        self.cusum_pressure = 0;
    }

    /// Roll back to conservative defaults (zero deltas).
    fn rollback(&mut self) {
        self.deltas = RetuningDeltas::default();
        self.rollback_count += 1;
        self.oscillation_count += 1;

        if self.oscillation_count >= REGIME_ROLLBACK_OSCILLATION_LIMIT {
            self.phase = RegimePhase::LockedConservative;
        } else {
            self.phase = RegimePhase::Rollback;
        }
    }

    /// Get the current combined CUSUM score.
    fn combined_score(&self) -> i64 {
        self.cusum_density + self.cusum_pressure
    }

    /// Get the current retuning deltas.
    fn current_deltas(&self) -> RetuningDeltas {
        self.deltas
    }

    /// Apply regime detector state to decode stats for observability.
    fn apply_to_stats(&self, stats: &mut DecodeStats) {
        stats.regime_score = self.combined_score();
        stats.regime_state = Some(self.phase.label());
        stats.regime_retune_count = self.retune_count;
        stats.regime_rollback_count = self.rollback_count;
        stats.regime_window_len = self.window.len();
        stats.regime_delta_density_bias = self.deltas.density_bias_delta;
        stats.regime_delta_pressure_bias = self.deltas.pressure_bias_delta;
        stats.regime_replay_ref = Some(REGIME_REPLAY_REF);
    }
}

/// Apply retuning deltas to the policy loss computation.
///
/// The deltas adjust the loss-model coefficients within bounded caps,
/// allowing the policy engine to adapt to workload regime shifts while
/// preserving deterministic replay semantics.
fn policy_losses_with_retuning(
    features: DecoderPolicyFeatures,
    n_cols: usize,
    deltas: RetuningDeltas,
) -> (u32, u32, u32) {
    if deltas.is_zero() {
        return policy_losses(features, n_cols);
    }

    let density = clamp_usize_to_u32(features.density_permille);
    let rank_deficit = clamp_usize_to_u32(features.rank_deficit_permille);
    let inactivation_pressure = clamp_usize_to_u32(features.inactivation_pressure_permille);
    let overhead = clamp_usize_to_u32(features.overhead_ratio_permille);

    // Apply bounded deltas to the baseline loss intercept and coefficients.
    // .max() calls guarantee non-negative values before unsigned conversion.
    let baseline_intercept = (400i32 + deltas.baseline_intercept_delta)
        .max(200)
        .unsigned_abs();
    let density_coeff = (3i32 + deltas.density_bias_delta).max(1).unsigned_abs();
    let pressure_coeff = (2i32 + deltas.pressure_bias_delta).max(1).unsigned_abs();

    let baseline_loss = baseline_intercept
        .saturating_add(density.saturating_mul(density_coeff))
        .saturating_add(rank_deficit.saturating_mul(4))
        .saturating_add(inactivation_pressure.saturating_mul(pressure_coeff))
        .saturating_add(overhead);

    // Aggressive modes use the same static model (retuning only adjusts the
    // conservative baseline to make mode selection more or less aggressive).
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

/// Choose runtime decoder policy with optional regime-shift retuning deltas.
fn choose_runtime_decoder_policy_retuned(
    n_rows: usize,
    n_cols: usize,
    dense_nonzeros: usize,
    unsupported_cols: usize,
    inactivation_pressure_permille: usize,
    deltas: RetuningDeltas,
) -> DecoderPolicyDecision {
    let features = compute_decoder_policy_features(
        n_rows,
        n_cols,
        dense_nonzeros,
        unsupported_cols,
        inactivation_pressure_permille,
    );

    let (baseline_loss, high_support_loss, mut block_schur_loss) =
        policy_losses_with_retuning(features, n_cols, deltas);

    if features.budget_exhausted {
        return DecoderPolicyDecision {
            mode: DecoderPolicyMode::ConservativeBaseline,
            features,
            baseline_loss,
            high_support_loss,
            block_schur_loss,
            reason: "policy_budget_exhausted_conservative",
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
        a[row_off..row_off + n_cols]
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
    if state.active_cols.contains(&col) && state.solved[col].is_none() {
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

const DENSE_COL_ABSENT: usize = usize::MAX;

#[inline]
fn build_dense_col_index_map(unsolved: &[usize]) -> Vec<usize> {
    let Some(max_col) = unsolved.iter().copied().max() else {
        return Vec::new();
    };
    let mut col_to_dense = vec![DENSE_COL_ABSENT; max_col.saturating_add(1)];
    for (dense_col, &col) in unsolved.iter().enumerate() {
        col_to_dense[col] = dense_col;
    }
    col_to_dense
}

#[inline]
fn dense_col_index(col_to_dense: &[usize], col: usize) -> Option<usize> {
    let dense_col = *col_to_dense.get(col)?;
    if dense_col == DENSE_COL_ABSENT {
        return None;
    }
    Some(dense_col)
}

fn sparse_first_dense_columns(
    equations: &[Equation],
    dense_rows: &[usize],
    unsolved: &[usize],
) -> Vec<usize> {
    if unsolved.len() < 2 {
        return unsolved.to_vec();
    }

    let col_to_dense = build_dense_col_index_map(unsolved);
    let mut support = vec![0usize; unsolved.len()];

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

    let (baseline_loss, high_support_loss, mut block_schur_loss) = policy_losses(features, n_cols);
    if features.budget_exhausted {
        return DecoderPolicyDecision {
            mode: DecoderPolicyMode::ConservativeBaseline,
            features,
            baseline_loss,
            high_support_loss,
            block_schur_loss,
            reason: "policy_budget_exhausted_conservative",
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
    }
}

const fn decoder_policy_mode_label(mode: DecoderPolicyMode) -> &'static str {
    match mode {
        DecoderPolicyMode::ConservativeBaseline => "conservative_baseline",
        DecoderPolicyMode::HighSupportFirst => "high_support_first",
        DecoderPolicyMode::BlockSchurLowRank => "block_schur_low_rank",
    }
}

fn apply_policy_decision_to_stats(stats: &mut DecodeStats, decision: DecoderPolicyDecision) {
    stats.policy_mode = Some(decoder_policy_mode_label(decision.mode));
    stats.policy_reason = Some(decision.reason);
    stats.policy_replay_ref = Some(POLICY_REPLAY_REF);
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
    a[row_off..row_off + n_cols]
        .iter()
        .filter(|coef| !coef.is_zero())
        .count()
}

#[inline]
fn should_use_sparse_row_update(pivot_nnz: usize, n_cols: usize) -> bool {
    if n_cols == 0 {
        return false;
    }

    // Explicit cost model: compare sparse-vs-dense column-touch counts with
    // a conservative overhead multiplier for sparse index iteration.
    pivot_nnz.saturating_mul(HYBRID_SPARSE_COST_DENOMINATOR)
        <= n_cols.saturating_mul(HYBRID_SPARSE_COST_NUMERATOR)
}

fn pivot_nonzero_columns(pivot_row: &[Gf256], n_cols: usize) -> Vec<usize> {
    let mut cols = Vec::with_capacity(n_cols.min(32));
    for (idx, coef) in pivot_row.iter().take(n_cols).enumerate() {
        if !coef.is_zero() {
            cols.push(idx);
        }
    }
    cols
}

fn sparse_update_columns_if_beneficial(pivot_row: &[Gf256], n_cols: usize) -> Option<Vec<usize>> {
    let mut cols = Vec::with_capacity(n_cols.clamp(1, 32));
    if sparse_update_columns_if_beneficial_into(pivot_row, n_cols, &mut cols) {
        Some(cols)
    } else {
        None
    }
}

fn sparse_update_columns_if_beneficial_into(
    pivot_row: &[Gf256],
    n_cols: usize,
    cols: &mut Vec<usize>,
) -> bool {
    cols.clear();
    if n_cols == 0 {
        return false;
    }

    // Equivalent threshold to should_use_sparse_row_update(pivot_nnz, n_cols).
    let threshold =
        n_cols.saturating_mul(HYBRID_SPARSE_COST_NUMERATOR) / HYBRID_SPARSE_COST_DENOMINATOR;

    if n_cols <= SMALL_ROW_DENSE_FASTPATH_COLS {
        // Very small rows are sensitive to per-pivot heap allocation overhead.
        // Track sparse indices in a fixed stack buffer and copy once.
        let mut small_cols = [0usize; SMALL_ROW_DENSE_FASTPATH_COLS];
        let mut sparse_nnz = 0usize;
        for (idx, coef) in pivot_row.iter().take(n_cols).enumerate() {
            if coef.is_zero() {
                continue;
            }
            if sparse_nnz == threshold {
                return false;
            }
            small_cols[sparse_nnz] = idx;
            sparse_nnz += 1;
        }
        cols.reserve(sparse_nnz.saturating_sub(cols.len()));
        cols.extend_from_slice(&small_cols[..sparse_nnz]);
        return true;
    }

    // For larger rows, one-pass collection avoids an extra scan on sparse pivots.
    for (idx, coef) in pivot_row.iter().take(n_cols).enumerate() {
        if coef.is_zero() {
            continue;
        }
        if cols.len() == threshold {
            cols.clear();
            return false;
        }
        cols.push(idx);
    }
    true
}

#[inline]
fn dense_update_start_col(pivot_row: &[Gf256], pivot_col: usize) -> usize {
    if pivot_row
        .iter()
        .take(pivot_col.min(pivot_row.len()))
        .any(|coef| !coef.is_zero())
    {
        0
    } else {
        pivot_col.min(pivot_row.len())
    }
}

#[inline]
fn eliminate_row_coefficients(
    row: &mut [Gf256],
    pivot_row: &[Gf256],
    factor: Gf256,
    pivot_col: usize,
    use_sparse: bool,
    sparse_cols: &[usize],
    dense_start_col: usize,
) {
    debug_assert_eq!(row.len(), pivot_row.len());
    debug_assert!(pivot_col < row.len());
    row[pivot_col] = Gf256::ZERO;

    if use_sparse {
        for &c in sparse_cols {
            if c == pivot_col {
                continue;
            }
            row[c] += factor * pivot_row[c];
        }
        return;
    }

    if dense_start_col == 0 {
        for c in 0..pivot_col {
            row[c] += factor * pivot_row[c];
        }
    }

    let tail_start = dense_start_col.max(pivot_col.saturating_add(1));
    for c in tail_start..row.len() {
        row[c] += factor * pivot_row[c];
    }
}

fn should_activate_hard_regime(n_rows: usize, n_cols: usize, a: &[Gf256]) -> bool {
    if n_cols < HARD_REGIME_MIN_COLS {
        return false;
    }

    let total_cells = n_rows.saturating_mul(n_cols);
    if total_cells == 0 {
        return false;
    }

    let nonzeros = matrix_nonzero_count(a);
    let dense =
        nonzeros.saturating_mul(100) >= total_cells.saturating_mul(HARD_REGIME_DENSITY_PERCENT);
    let near_square = n_rows <= n_cols.saturating_add(HARD_REGIME_NEAR_SQUARE_EXTRA_ROWS);

    dense || near_square
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

    let mut best: Option<(usize, usize, usize)> = None;
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
        match best {
            None => best = Some((row, cross_block_nnz, nnz)),
            Some((_best_row, best_cross, _best_nnz)) if cross_block_nnz < best_cross => {
                best = Some((row, cross_block_nnz, nnz));
            }
            Some((_best_row, best_cross, best_nnz))
                if cross_block_nnz == best_cross && nnz < best_nnz =>
            {
                best = Some((row, cross_block_nnz, nnz));
            }
            Some((best_row, best_cross, best_nnz))
                if cross_block_nnz == best_cross && nnz == best_nnz && row < best_row =>
            {
                best = Some((row, cross_block_nnz, nnz));
            }
            _ => {}
        }
    }

    best.map(|(row, _, _)| row)
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
    regime_detector: parking_lot::Mutex<RegimeDetector>,
}

impl InactivationDecoder {
    /// Create a new decoder for the given parameters.
    #[must_use]
    pub fn new(k: usize, symbol_size: usize, seed: u64) -> Self {
        let params = SystematicParams::for_source_block(k, symbol_size);
        Self {
            params,
            seed,
            dense_factor_cache: parking_lot::Mutex::new(DenseFactorCache::default()),
            regime_detector: parking_lot::Mutex::new(RegimeDetector::default()),
        }
    }

    /// Returns the encoding parameters.
    #[must_use]
    pub const fn params(&self) -> &SystematicParams {
        &self.params
    }

    fn validate_input(&self, symbols: &[ReceivedSymbol]) -> Result<(), DecodeError> {
        let l = self.params.l;
        let symbol_size = self.params.symbol_size;

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

            if sym.columns.len() != sym.coefficients.len() {
                return Err(DecodeError::SymbolEquationArityMismatch {
                    esi: sym.esi,
                    columns: sym.columns.len(),
                    coefficients: sym.coefficients.len(),
                });
            }

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

    fn verify_decoded_output(
        &self,
        symbols: &[ReceivedSymbol],
        intermediate: &[Vec<u8>],
    ) -> Result<(), DecodeError> {
        let symbol_size = self.params.symbol_size;
        // Reuse a single scratch buffer across rows to avoid per-symbol
        // heap allocation in decode hot paths.
        let mut reconstructed = vec![0u8; symbol_size];

        for sym in symbols {
            if sym.is_source
                && sym.columns.len() == 1
                && sym.coefficients.len() == 1
                && sym.coefficients[0] == Gf256::ONE
            {
                let source_col = sym.columns[0];
                let expected = &intermediate[source_col];
                if let Some(byte_index) = first_mismatch_byte(expected, &sym.data) {
                    return Err(DecodeError::CorruptDecodedOutput {
                        esi: sym.esi,
                        byte_index,
                        expected: expected[byte_index],
                        actual: sym.data[byte_index],
                    });
                }
                continue;
            }

            reconstructed.fill(0);
            for (&column, &coefficient) in sym.columns.iter().zip(sym.coefficients.iter()) {
                if coefficient.is_zero() {
                    continue;
                }
                gf256_addmul_slice(&mut reconstructed, &intermediate[column], coefficient);
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
    /// `symbols` should contain at least `L` symbols (K source + S LDPC + H HDPC overhead).
    /// Returns the decoded source symbols on success.
    pub fn decode(&self, symbols: &[ReceivedSymbol]) -> Result<DecodeResult, DecodeError> {
        let k = self.params.k;
        let symbol_size = self.params.symbol_size;

        self.validate_input(symbols)?;

        // Build decoder state
        let mut state = self.build_state(symbols);

        // Phase 1: Peeling
        Self::peel(&mut state);

        // Phase 2: Inactivation + Gaussian elimination
        let solve_result = self.inactivate_and_solve(&mut state);

        // F6: Feed observation to regime detector and apply stats.
        // The observation is recorded regardless of decode success/failure.
        {
            let features = DecoderPolicyFeatures {
                density_permille: state.stats.policy_density_permille,
                rank_deficit_permille: state.stats.policy_rank_deficit_permille,
                inactivation_pressure_permille: state.stats.policy_inactivation_pressure_permille,
                overhead_ratio_permille: state.stats.policy_overhead_ratio_permille,
                budget_exhausted: state.stats.policy_budget_exhausted,
            };
            let policy_mode = match state.stats.policy_mode {
                Some("high_support_first") => DecoderPolicyMode::HighSupportFirst,
                Some("block_schur_low_rank") => DecoderPolicyMode::BlockSchurLowRank,
                _ => DecoderPolicyMode::ConservativeBaseline,
            };
            let obs = RegimeObservation {
                features,
                decode_success: solve_result.is_ok(),
                policy_mode,
            };
            let mut detector = self.regime_detector.lock();
            let _deltas = detector.observe(obs);
            detector.apply_to_stats(&mut state.stats);
        }

        // Propagate solve failure after regime observation.
        solve_result?;

        // Extract results
        let intermediate: Vec<Vec<u8>> = state
            .solved
            .into_iter()
            .map(|opt| opt.unwrap_or_else(|| vec![0u8; symbol_size]))
            .collect();
        self.verify_decoded_output(symbols, &intermediate)?;

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
        if let Err(err) = self.validate_input(symbols) {
            proof_builder.set_failure(FailureReason::from(&err));
            return Err((err, proof_builder.build()));
        }

        // Build decoder state
        let mut state = self.build_state(symbols);

        // Phase 1: Peeling with proof capture
        Self::peel_with_proof(&mut state, proof_builder.peeling_mut());

        // Phase 2: Inactivation + Gaussian elimination with proof capture
        let solve_result =
            self.inactivate_and_solve_with_proof(&mut state, proof_builder.elimination_mut());

        // F6: Feed observation to regime detector and apply stats.
        {
            let features = DecoderPolicyFeatures {
                density_permille: state.stats.policy_density_permille,
                rank_deficit_permille: state.stats.policy_rank_deficit_permille,
                inactivation_pressure_permille: state.stats.policy_inactivation_pressure_permille,
                overhead_ratio_permille: state.stats.policy_overhead_ratio_permille,
                budget_exhausted: state.stats.policy_budget_exhausted,
            };
            let policy_mode = match state.stats.policy_mode {
                Some("high_support_first") => DecoderPolicyMode::HighSupportFirst,
                Some("block_schur_low_rank") => DecoderPolicyMode::BlockSchurLowRank,
                _ => DecoderPolicyMode::ConservativeBaseline,
            };
            let obs = RegimeObservation {
                features,
                decode_success: solve_result.is_ok(),
                policy_mode,
            };
            let mut detector = self.regime_detector.lock();
            let _deltas = detector.observe(obs);
            detector.apply_to_stats(&mut state.stats);
        }

        if let Err(err) = solve_result {
            let reason = failure_reason_with_trace(&err, proof_builder.elimination_mut());
            proof_builder.set_failure(reason);
            return Err((err, proof_builder.build()));
        }

        // Extract results
        let intermediate: Vec<Vec<u8>> = state
            .solved
            .into_iter()
            .map(|opt| opt.unwrap_or_else(|| vec![0u8; symbol_size]))
            .collect();
        if let Err(err) = self.verify_decoded_output(symbols, &intermediate) {
            proof_builder.set_failure(FailureReason::from(&err));
            return Err((err, proof_builder.build()));
        }

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

    fn dense_factor_with_cache(
        &self,
        equations: &[Equation],
        dense_rows: &[usize],
        unsolved: &[usize],
    ) -> (DenseFactorArtifact, DenseFactorCacheObservation) {
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
        let artifact =
            DenseFactorArtifact::new(sparse_first_dense_columns(equations, dense_rows, unsolved));
        let (result, cache_entries) = {
            let mut cache = self.dense_factor_cache.lock();
            let result = cache.insert(signature, artifact.clone());
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

            state.active_cols.remove(&col);
            state.stats.peeled += 1;
            on_solved(col);

            // Propagate to other equations: subtract col's contribution
            let active_cols = &state.active_cols;
            let solved = &state.solved;
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

                if !queued[i] && !eq.used && eq.degree() == 1 {
                    let next_col = eq.terms[0].0;
                    if active_cols.contains(&next_col) && solved[next_col].is_none() {
                        queue.push_back(i);
                        queued[i] = true;
                        state.stats.peel_queue_pushes += 1;
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
            .active_cols
            .iter()
            .filter(|&&col| state.solved[col].is_none())
            .copied()
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

        // Mark all remaining unsolved columns as inactive
        for &col in &unsolved {
            state.inactive_cols.insert(col);
            state.active_cols.remove(&col);
            state.stats.inactivated += 1;
        }

        // Reorder dense elimination columns deterministically and reuse cached
        // dense skeleton metadata when signatures match.
        let (dense_factor, cache_observation) =
            self.dense_factor_with_cache(&state.equations, &dense_rows, &unsolved);
        apply_dense_factor_cache_observation(&mut state.stats, cache_observation);
        let DenseFactorArtifact {
            dense_cols,
            col_to_dense,
        } = dense_factor;

        // Build dense submatrix for Gaussian elimination
        // Rows = unused equations, Columns = unsolved columns
        let n_rows = dense_rows.len();
        let n_cols = dense_cols.len();
        let inactivation_pressure_permille =
            unsolved.len().saturating_mul(1000) / state.params.l.max(1);
        state.stats.dense_core_rows = n_rows;
        state.stats.dense_core_cols = n_cols;

        if n_rows < n_cols {
            return Err(DecodeError::InsufficientSymbols {
                received: n_rows,
                required: n_cols,
            });
        }

        // Build flat row-major dense matrix A and RHS vector b.
        // Flat layout avoids per-row heap allocation and improves cache locality.
        // Move (take) RHS data from state instead of cloning to avoid O(n_rows * symbol_size)
        // heap allocation in this hot path.
        let mut a = vec![Gf256::ZERO; n_rows * n_cols];
        let mut dense_nonzeros = 0usize;
        let mut dense_col_support = vec![0usize; n_cols];
        let mut b: Vec<Vec<u8>> = Vec::with_capacity(n_rows);

        for (row, &eq_idx) in dense_rows.iter().enumerate() {
            let row_off = row * n_cols;
            for &(col, coef) in &state.equations[eq_idx].terms {
                if let Some(dense_col) = dense_col_index(&col_to_dense, col) {
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

        // F6: Apply regime-shift retuning deltas to the policy decision.
        let regime_deltas = self.regime_detector.lock().current_deltas();
        let decision = choose_runtime_decoder_policy_retuned(
            n_rows,
            n_cols,
            dense_nonzeros,
            unsupported_cols,
            inactivation_pressure_permille,
            regime_deltas,
        );
        apply_policy_decision_to_stats(&mut state.stats, decision);
        let mut hard_regime = !matches!(decision.mode, DecoderPolicyMode::ConservativeBaseline);
        let mut hard_plan = match decision.mode {
            DecoderPolicyMode::ConservativeBaseline | DecoderPolicyMode::HighSupportFirst => {
                HardRegimePlan::Markowitz
            }
            DecoderPolicyMode::BlockSchurLowRank => select_hard_regime_plan(n_rows, n_cols, &a),
        };
        let retry_snapshot = (!hard_regime
            || matches!(hard_plan, HardRegimePlan::BlockSchurLowRank { .. }))
        .then(|| (a.clone(), snapshot_dense_rhs(&b, symbol_size)));
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
            let mut sparse_cols = Vec::with_capacity(n_cols.clamp(1, 32));
            let mut gauss_ops = 0usize;
            let mut pivots_selected = 0usize;
            let mut markowitz_pivots = 0usize;
            let mut elimination_error = None;

            for col in 0..n_cols {
                let pivot =
                    select_pivot_row(&a, n_rows, n_cols, col, &row_used, hard_regime, hard_plan);
                let Some(prow) = pivot else {
                    elimination_error = Some(singular_matrix_error(&dense_cols, col));
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
                let use_sparse = sparse_update_columns_if_beneficial_into(
                    &pivot_buf[..n_cols],
                    n_cols,
                    &mut sparse_cols,
                );
                let dense_start_col = dense_update_start_col(&pivot_buf[..n_cols], col);

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
                    eliminate_row_coefficients(
                        &mut a[row_off..row_off + n_cols],
                        &pivot_buf[..n_cols],
                        factor,
                        col,
                        use_sparse,
                        &sparse_cols,
                        dense_start_col,
                    );
                    gf256_addmul_slice(rhs, &pivot_rhs[..symbol_size], factor);
                    gauss_ops += 1;
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
                    hard_plan = select_hard_regime_plan(n_rows, n_cols, &a);
                    state.stats.hard_regime_branch = Some(hard_plan.label());
                    state.stats.hard_regime_fallbacks += 1;
                    state.stats.hard_regime_conservative_fallback_reason =
                        Some("fallback_after_baseline_failure");
                    if let Some((base_a, base_b)) = retry_snapshot.as_ref() {
                        a.clone_from(base_a);
                        restore_dense_rhs(&mut b, base_b, symbol_size);
                    }
                    continue;
                }
                if matches!(hard_plan, HardRegimePlan::BlockSchurLowRank { .. }) {
                    hard_plan = HardRegimePlan::Markowitz;
                    state.stats.hard_regime_fallbacks += 1;
                    state.stats.hard_regime_conservative_fallback_reason =
                        Some("block_schur_failed_to_converge");
                    if let Some((base_a, base_b)) = retry_snapshot.as_ref() {
                        a.clone_from(base_a);
                        restore_dense_rhs(&mut b, base_b, symbol_size);
                    }
                    continue;
                }
                return Err(err);
            }
            break;
        }

        // Extract solutions: move RHS vectors instead of cloning
        for (dense_col, &col) in dense_cols.iter().enumerate() {
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
    #[allow(clippy::too_many_lines)]
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
        let (dense_rows, dropped_zero_rows) = build_dense_core_rows(state, &unused_eqs, &unsolved)?;
        state.stats.dense_core_dropped_rows += dropped_zero_rows;

        // Mark all remaining unsolved columns as inactive
        for &col in &unsolved {
            state.inactive_cols.insert(col);
            state.active_cols.remove(&col);
            state.stats.inactivated += 1;
            // Record inactivation in proof trace
            trace.record_inactivation(col);
        }

        // Reorder dense elimination columns deterministically and reuse cached
        // dense skeleton metadata when signatures match.
        let (dense_factor, cache_observation) =
            self.dense_factor_with_cache(&state.equations, &dense_rows, &unsolved);
        apply_dense_factor_cache_observation(&mut state.stats, cache_observation);
        let DenseFactorArtifact {
            dense_cols,
            col_to_dense,
        } = dense_factor;

        // Build dense submatrix for Gaussian elimination
        // Rows = unused equations, Columns = unsolved columns
        let n_rows = dense_rows.len();
        let n_cols = dense_cols.len();
        let inactivation_pressure_permille =
            unsolved.len().saturating_mul(1000) / state.params.l.max(1);
        state.stats.dense_core_rows = n_rows;
        state.stats.dense_core_cols = n_cols;

        if n_rows < n_cols {
            return Err(DecodeError::InsufficientSymbols {
                received: n_rows,
                required: n_cols,
            });
        }

        // Build flat row-major dense matrix A and RHS vector b.
        // Move (take) RHS data from state instead of cloning to avoid O(n_rows * symbol_size)
        // heap allocation in this hot path.
        let mut a = vec![Gf256::ZERO; n_rows * n_cols];
        let mut dense_nonzeros = 0usize;
        let mut dense_col_support = vec![0usize; n_cols];
        let mut b: Vec<Vec<u8>> = Vec::with_capacity(n_rows);

        for (row, &eq_idx) in dense_rows.iter().enumerate() {
            let row_off = row * n_cols;
            for &(col, coef) in &state.equations[eq_idx].terms {
                if let Some(dense_col) = dense_col_index(&col_to_dense, col) {
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

        trace.set_strategy(InactivationStrategy::AllAtOnce);
        // F6: Apply regime-shift retuning deltas to the policy decision.
        let regime_deltas = self.regime_detector.lock().current_deltas();
        let decision = choose_runtime_decoder_policy_retuned(
            n_rows,
            n_cols,
            dense_nonzeros,
            unsupported_cols,
            inactivation_pressure_permille,
            regime_deltas,
        );
        apply_policy_decision_to_stats(&mut state.stats, decision);
        let mut hard_regime = !matches!(decision.mode, DecoderPolicyMode::ConservativeBaseline);
        let mut hard_plan = match decision.mode {
            DecoderPolicyMode::ConservativeBaseline | DecoderPolicyMode::HighSupportFirst => {
                HardRegimePlan::Markowitz
            }
            DecoderPolicyMode::BlockSchurLowRank => select_hard_regime_plan(n_rows, n_cols, &a),
        };
        let retry_snapshot = (!hard_regime
            || matches!(hard_plan, HardRegimePlan::BlockSchurLowRank { .. }))
        .then(|| (a.clone(), snapshot_dense_rhs(&b, symbol_size)));
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
            let mut sparse_cols = Vec::with_capacity(n_cols.clamp(1, 32));
            let mut gauss_ops = 0usize;
            let mut pivots_selected = 0usize;
            let mut markowitz_pivots = 0usize;
            let mut elimination_error = None;

            for col in 0..n_cols {
                let pivot =
                    select_pivot_row(&a, n_rows, n_cols, col, &row_used, hard_regime, hard_plan);
                let Some(prow) = pivot else {
                    elimination_error = Some(singular_matrix_error(&dense_cols, col));
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
                let use_sparse = sparse_update_columns_if_beneficial_into(
                    &pivot_buf[..n_cols],
                    n_cols,
                    &mut sparse_cols,
                );
                let dense_start_col = dense_update_start_col(&pivot_buf[..n_cols], col);

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
                    eliminate_row_coefficients(
                        &mut a[row_off..row_off + n_cols],
                        &pivot_buf[..n_cols],
                        factor,
                        col,
                        use_sparse,
                        &sparse_cols,
                        dense_start_col,
                    );
                    gf256_addmul_slice(rhs, &pivot_rhs[..symbol_size], factor);
                    gauss_ops += 1;
                    // Record row operation in proof trace
                    trace.record_row_op();
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
                    hard_plan = select_hard_regime_plan(n_rows, n_cols, &a);
                    state.stats.hard_regime_branch = Some(hard_plan.label());
                    state.stats.hard_regime_fallbacks += 1;
                    state.stats.hard_regime_conservative_fallback_reason =
                        Some("fallback_after_baseline_failure");
                    trace.record_strategy_transition(
                        InactivationStrategy::AllAtOnce,
                        hard_plan.strategy(),
                        "fallback_after_baseline_failure",
                    );
                    trace.pivots = 0;
                    trace.pivot_events.clear();
                    trace.row_ops = 0;
                    trace.truncated = false;
                    if let Some((base_a, base_b)) = retry_snapshot.as_ref() {
                        a.clone_from(base_a);
                        restore_dense_rhs(&mut b, base_b, symbol_size);
                    }
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
                    trace.truncated = false;
                    if let Some((base_a, base_b)) = retry_snapshot.as_ref() {
                        a.clone_from(base_a);
                        restore_dense_rhs(&mut b, base_b, symbol_size);
                    }
                    continue;
                }
                return Err(err);
            }
            break;
        }

        // Extract solutions: move RHS vectors instead of cloning
        for (dense_col, &col) in dense_cols.iter().enumerate() {
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

fn first_mismatch_byte(expected: &[u8], actual: &[u8]) -> Option<usize> {
    expected
        .iter()
        .zip(actual.iter())
        .position(|(expected, actual)| expected != actual)
}

fn snapshot_dense_rhs(rows: &[Vec<u8>], symbol_size: usize) -> Vec<u8> {
    let mut snapshot = vec![0u8; rows.len().saturating_mul(symbol_size)];
    for (row_idx, row) in rows.iter().enumerate() {
        debug_assert_eq!(row.len(), symbol_size);
        let off = row_idx * symbol_size;
        snapshot[off..off + symbol_size].copy_from_slice(row);
    }
    snapshot
}

fn restore_dense_rhs(rows: &mut [Vec<u8>], snapshot: &[u8], symbol_size: usize) {
    debug_assert_eq!(snapshot.len(), rows.len().saturating_mul(symbol_size));
    for (row_idx, row) in rows.iter_mut().enumerate() {
        debug_assert_eq!(row.len(), symbol_size);
        let off = row_idx * symbol_size;
        row.copy_from_slice(&snapshot[off..off + symbol_size]);
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
    use crate::raptorq::test_log_schema::{UnitDecodeStats, UnitLogEntry, validate_unit_log_json};

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

    fn to_unit_decode_stats(k: usize, dropped: usize, stats: &DecodeStats) -> UnitDecodeStats {
        UnitDecodeStats {
            k,
            loss_pct: dropped.saturating_mul(100) / k.max(1),
            dropped,
            peeled: stats.peeled,
            inactivated: stats.inactivated,
            gauss_ops: stats.gauss_ops,
            pivots: stats.pivots_selected,
            peel_queue_pushes: stats.peel_queue_pushes,
            peel_queue_pops: stats.peel_queue_pops,
            peel_frontier_peak: stats.peel_frontier_peak,
            dense_core_rows: stats.dense_core_rows,
            dense_core_cols: stats.dense_core_cols,
            dense_core_dropped_rows: stats.dense_core_dropped_rows,
            fallback_reason: stats
                .hard_regime_conservative_fallback_reason
                .or(stats.peeling_fallback_reason)
                .unwrap_or("none")
                .to_string(),
            hard_regime_activated: stats.hard_regime_activated,
            hard_regime_branch: stats.hard_regime_branch.unwrap_or("none").to_string(),
            hard_regime_fallbacks: stats.hard_regime_fallbacks,
            conservative_fallback_reason: stats
                .hard_regime_conservative_fallback_reason
                .unwrap_or("none")
                .to_string(),
        }
    }

    fn emit_decoder_unit_log(
        scenario_id: &str,
        seed: u64,
        parameter_set: &str,
        outcome: &str,
        repro_command: &str,
        stats: Option<UnitDecodeStats>,
    ) -> String {
        let mut entry = UnitLogEntry::new(
            scenario_id,
            seed,
            parameter_set,
            "replay:rq-track-c-decoder-unit-v1",
            outcome,
        )
        .with_repro_command(repro_command)
        .with_artifact_path("artifacts/raptorq_track_c_decoder_unit_v1.json");
        if let Some(stats) = stats {
            entry = entry.with_decode_stats(stats);
        }

        let json = entry.to_json().expect("serialize decoder unit log entry");
        let violations = validate_unit_log_json(&json);
        let context = entry.to_context_string();
        assert!(
            violations.is_empty(),
            "{context}: unit log schema violations: {violations:?}"
        );
        json
    }

    #[test]
    fn dense_col_index_map_handles_sparse_columns() {
        let unsolved = vec![2, 7, 11];
        let col_to_dense = build_dense_col_index_map(&unsolved);

        assert_eq!(dense_col_index(&col_to_dense, 2), Some(0));
        assert_eq!(dense_col_index(&col_to_dense, 7), Some(1));
        assert_eq!(dense_col_index(&col_to_dense, 11), Some(2));
        assert_eq!(dense_col_index(&col_to_dense, 3), None);
        assert_eq!(dense_col_index(&col_to_dense, 99), None);
    }

    #[test]
    fn sparse_first_dense_columns_orders_by_support_then_column() {
        let equations = vec![
            Equation::new(vec![7, 11], vec![Gf256::ONE, Gf256::ONE]),
            Equation::new(vec![2, 7], vec![Gf256::ONE, Gf256::ONE]),
            Equation::new(vec![7], vec![Gf256::ONE]),
            Equation::new(vec![2], vec![Gf256::ONE]),
        ];
        let dense_rows = vec![0, 1, 2, 3];
        let unsolved = vec![7, 2, 11];

        let ordered = sparse_first_dense_columns(&equations, &dense_rows, &unsolved);

        // supports: col 11 -> 1, col 2 -> 2, col 7 -> 3
        assert_eq!(ordered, vec![11, 2, 7]);
    }

    #[test]
    fn dense_factor_signature_detects_equation_changes() {
        let equations_a = vec![Equation::new(vec![0, 1], vec![Gf256::ONE, Gf256::new(7)])];
        let equations_b = vec![Equation::new(vec![0, 1], vec![Gf256::ONE, Gf256::new(9)])];
        let dense_rows = vec![0];
        let unsolved = vec![0, 1];

        let sig_a = DenseFactorSignature::from_equations(&equations_a, &dense_rows, &unsolved);
        let sig_b = DenseFactorSignature::from_equations(&equations_b, &dense_rows, &unsolved);

        assert_ne!(sig_a, sig_b);
    }

    #[test]
    fn dense_factor_cache_requires_strict_signature_match() {
        let equations_a = vec![Equation::new(vec![0, 1], vec![Gf256::ONE, Gf256::new(7)])];
        let equations_b = vec![Equation::new(vec![0, 1], vec![Gf256::ONE, Gf256::new(9)])];
        let dense_rows = vec![0];
        let unsolved = vec![0, 1];

        let sig_a = DenseFactorSignature::from_equations(&equations_a, &dense_rows, &unsolved);
        let sig_b = DenseFactorSignature::from_equations(&equations_b, &dense_rows, &unsolved);

        let mut cache = DenseFactorCache::default();
        assert_eq!(
            cache.insert(sig_a.clone(), DenseFactorArtifact::new(vec![1, 0])),
            DenseFactorCacheResult::MissInserted
        );
        assert_eq!(
            cache.lookup(&sig_a),
            DenseFactorCacheLookup::Hit(DenseFactorArtifact::new(vec![1, 0]))
        );
        assert_eq!(cache.lookup(&sig_b), DenseFactorCacheLookup::MissNoEntry);
    }

    #[test]
    fn dense_factor_cache_detects_fingerprint_collision() {
        let equations_a = vec![Equation::new(vec![0, 1], vec![Gf256::ONE, Gf256::new(7)])];
        let equations_b = vec![Equation::new(vec![0, 1], vec![Gf256::ONE, Gf256::new(9)])];
        let dense_rows = vec![0];
        let unsolved = vec![0, 1];

        let sig_a = DenseFactorSignature::from_equations(&equations_a, &dense_rows, &unsolved);
        let mut sig_b = DenseFactorSignature::from_equations(&equations_b, &dense_rows, &unsolved);
        sig_b.fingerprint = sig_a.fingerprint;

        let mut cache = DenseFactorCache::default();
        assert_eq!(
            cache.insert(sig_a, DenseFactorArtifact::new(vec![1, 0])),
            DenseFactorCacheResult::MissInserted
        );
        assert_eq!(
            cache.lookup(&sig_b),
            DenseFactorCacheLookup::MissFingerprintCollision
        );
    }

    #[test]
    fn dense_factor_cache_evicts_oldest_entry_at_capacity() {
        let mut cache = DenseFactorCache::default();
        let mut first_signature = None;

        for idx in 0..=DENSE_FACTOR_CACHE_CAPACITY {
            let signature = DenseFactorSignature {
                fingerprint: idx as u64,
                unsolved: vec![idx],
                row_terms: vec![vec![(idx, 1)]],
            };
            if idx == 0 {
                first_signature = Some(signature.clone());
            }
            let expected = if idx + 1 > DENSE_FACTOR_CACHE_CAPACITY {
                DenseFactorCacheResult::MissEvicted
            } else {
                DenseFactorCacheResult::MissInserted
            };
            assert_eq!(
                cache.insert(signature, DenseFactorArtifact::new(vec![idx])),
                expected
            );
        }

        assert_eq!(cache.len(), DENSE_FACTOR_CACHE_CAPACITY);
        assert_eq!(
            cache.lookup(&first_signature.expect("first signature recorded")),
            DenseFactorCacheLookup::MissNoEntry
        );
    }

    #[test]
    fn hybrid_cost_model_prefers_sparse_for_low_support() {
        assert!(should_use_sparse_row_update(3, 8));
        assert!(should_use_sparse_row_update(6, 10));
        assert!(!should_use_sparse_row_update(7, 10));
        assert!(!should_use_sparse_row_update(1, 0));
    }

    #[test]
    fn pivot_nonzero_columns_returns_stable_sorted_positions() {
        let row = vec![
            Gf256::ZERO,
            Gf256::ONE,
            Gf256::ZERO,
            Gf256::ONE,
            Gf256::ONE,
            Gf256::ZERO,
        ];
        let cols = pivot_nonzero_columns(&row, row.len());
        assert_eq!(cols, vec![1, 3, 4]);
    }

    #[test]
    fn sparse_update_columns_if_beneficial_matches_threshold() {
        // For n_cols=10 and ratio 3/5, sparse path should accept up to 6 non-zero entries.
        let row_sparse = vec![
            Gf256::ONE,
            Gf256::ONE,
            Gf256::ZERO,
            Gf256::ONE,
            Gf256::ZERO,
            Gf256::ONE,
            Gf256::ONE,
            Gf256::ONE,
            Gf256::ZERO,
            Gf256::ZERO,
        ];
        let row_dense = vec![
            Gf256::ONE,
            Gf256::ONE,
            Gf256::ONE,
            Gf256::ONE,
            Gf256::ONE,
            Gf256::ONE,
            Gf256::ONE,
            Gf256::ZERO,
            Gf256::ZERO,
            Gf256::ZERO,
        ];

        let sparse_cols = sparse_update_columns_if_beneficial(&row_sparse, 10)
            .expect("row_sparse should take sparse update path");
        assert_eq!(sparse_cols, vec![0, 1, 3, 5, 6, 7]);
        assert!(sparse_update_columns_if_beneficial(&row_dense, 10).is_none());
    }

    #[test]
    fn sparse_update_columns_into_reuses_and_clears_buffer() {
        let row_sparse = vec![
            Gf256::ONE,
            Gf256::ZERO,
            Gf256::ONE,
            Gf256::ZERO,
            Gf256::ONE,
            Gf256::ZERO,
            Gf256::ONE,
            Gf256::ZERO,
            Gf256::ZERO,
            Gf256::ZERO,
        ];
        let row_dense = vec![
            Gf256::ONE,
            Gf256::ONE,
            Gf256::ONE,
            Gf256::ONE,
            Gf256::ONE,
            Gf256::ONE,
            Gf256::ONE,
            Gf256::ZERO,
            Gf256::ZERO,
            Gf256::ZERO,
        ];

        let mut cols = vec![42, 99];
        assert!(sparse_update_columns_if_beneficial_into(
            &row_sparse,
            10,
            &mut cols
        ));
        assert_eq!(cols, vec![0, 2, 4, 6]);

        assert!(!sparse_update_columns_if_beneficial_into(
            &row_dense, 10, &mut cols
        ));
        assert!(
            cols.is_empty(),
            "dense path must clear stale sparse indices"
        );
    }

    #[test]
    fn sparse_update_columns_branch_boundary_consistent() {
        // n=32 uses the small-row stack-buffer path.
        let mut row_32_sparse = vec![Gf256::ZERO; 32];
        for coef in row_32_sparse.iter_mut().take(19) {
            *coef = Gf256::ONE;
        }
        let mut cols = Vec::new();
        assert!(sparse_update_columns_if_beneficial_into(
            &row_32_sparse,
            32,
            &mut cols
        ));
        assert_eq!(cols.len(), 19);

        let mut row_32_dense = row_32_sparse.clone();
        row_32_dense[19] = Gf256::ONE;
        assert!(!sparse_update_columns_if_beneficial_into(
            &row_32_dense,
            32,
            &mut cols
        ));
        assert!(
            cols.is_empty(),
            "dense path must clear stale sparse indices at boundary"
        );

        // n=33 uses the large-row path and should preserve the same threshold semantics.
        let mut row_33_sparse = vec![Gf256::ZERO; 33];
        for coef in row_33_sparse.iter_mut().take(19) {
            *coef = Gf256::ONE;
        }
        assert!(sparse_update_columns_if_beneficial_into(
            &row_33_sparse,
            33,
            &mut cols
        ));
        assert_eq!(cols.len(), 19);

        let mut row_33_dense = row_33_sparse.clone();
        row_33_dense[19] = Gf256::ONE;
        assert!(!sparse_update_columns_if_beneficial_into(
            &row_33_dense,
            33,
            &mut cols
        ));
        assert!(
            cols.is_empty(),
            "dense path must clear stale sparse indices beyond boundary"
        );
    }

    #[test]
    fn dense_update_start_col_prefers_suffix_when_prefix_zero() {
        let mut pivot = vec![Gf256::ZERO; 12];
        for coef in pivot.iter_mut().skip(5) {
            *coef = Gf256::ONE;
        }
        assert_eq!(dense_update_start_col(&pivot, 5), 5);
    }

    #[test]
    fn dense_update_start_col_falls_back_to_zero_when_prefix_has_signal() {
        let mut pivot = vec![Gf256::ZERO; 12];
        pivot[2] = Gf256::ONE;
        pivot[5] = Gf256::ONE;
        assert_eq!(dense_update_start_col(&pivot, 5), 0);
    }

    #[test]
    fn dense_row_update_suffix_matches_full_manual_when_prefix_zero() {
        let pivot_row = vec![
            Gf256::ZERO,
            Gf256::ZERO,
            Gf256::ZERO,
            Gf256::ZERO,
            Gf256::ZERO,
            Gf256::new(0x55),
            Gf256::new(0x66),
            Gf256::new(0x77),
            Gf256::new(0x88),
            Gf256::new(0x99),
            Gf256::new(0xaa),
            Gf256::new(0xbb),
        ];
        let n_cols = pivot_row.len();
        assert!(
            sparse_update_columns_if_beneficial(&pivot_row, n_cols).is_none(),
            "test requires dense branch eligibility"
        );

        let factor = Gf256::new(0x5d);
        let base_row = vec![
            Gf256::new(0x0f),
            Gf256::new(0x10),
            Gf256::new(0x20),
            Gf256::new(0x30),
            Gf256::new(0x40),
            Gf256::new(0x50),
            Gf256::new(0x60),
            Gf256::new(0x70),
            Gf256::new(0x80),
            Gf256::new(0x90),
            Gf256::new(0xa0),
            Gf256::new(0xb0),
        ];

        let mut manual = base_row.clone();
        for c in 0..n_cols {
            manual[c] += factor * pivot_row[c];
        }

        let dense_start_col = dense_update_start_col(&pivot_row, 5);
        let mut suffix_only = base_row;
        for c in dense_start_col..n_cols {
            suffix_only[c] += factor * pivot_row[c];
        }

        assert_eq!(
            suffix_only, manual,
            "suffix-only dense update must match full-row elimination math when prefix is zero"
        );
    }

    #[test]
    fn eliminate_row_coefficients_matches_manual_for_sparse_and_dense_paths() {
        let pivot_col = 3usize;
        let factor = Gf256::new(0x5d);
        let pivot_row = vec![
            Gf256::new(0x10),
            Gf256::new(0x20),
            Gf256::new(0x30),
            Gf256::ONE,
            Gf256::new(0x40),
            Gf256::new(0x50),
            Gf256::new(0x60),
            Gf256::new(0x70),
        ];
        let row = vec![
            Gf256::new(0x01),
            Gf256::new(0x02),
            Gf256::new(0x03),
            Gf256::new(0x04),
            Gf256::new(0x05),
            Gf256::new(0x06),
            Gf256::new(0x07),
            Gf256::new(0x08),
        ];

        let mut expected = row.clone();
        for c in 0..pivot_row.len() {
            expected[c] += factor * pivot_row[c];
        }
        expected[pivot_col] = Gf256::ZERO;

        let mut dense_actual = row.clone();
        eliminate_row_coefficients(
            &mut dense_actual,
            &pivot_row,
            factor,
            pivot_col,
            false,
            &[],
            0,
        );
        assert_eq!(
            dense_actual, expected,
            "dense elimination helper must match manual elimination"
        );

        let sparse_cols: Vec<usize> = (0..pivot_row.len())
            .filter(|&c| !pivot_row[c].is_zero())
            .collect();
        let mut sparse_actual = row;
        eliminate_row_coefficients(
            &mut sparse_actual,
            &pivot_row,
            factor,
            pivot_col,
            true,
            &sparse_cols,
            pivot_col,
        );
        assert_eq!(
            sparse_actual, expected,
            "sparse elimination helper must match manual elimination"
        );
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
    fn decode_repair_only_hits_dense_factor_cache_on_second_run() {
        let k = 4;
        let symbol_size = 16;
        let seed = 99u64;

        let source = make_source_data(k, symbol_size);
        let encoder = SystematicEncoder::new(&source, symbol_size, seed).unwrap();
        let decoder = InactivationDecoder::new(k, symbol_size, seed);
        let l = decoder.params().l;

        let mut received = decoder.constraint_symbols();
        for esi in (k as u32)..(k as u32 + l as u32) {
            let (cols, coefs) = decoder.repair_equation(esi);
            let repair_data = encoder.repair_symbol(esi);
            received.push(ReceivedSymbol::repair(esi, cols, coefs, repair_data));
        }

        let first = decoder
            .decode(&received)
            .expect("first decode should succeed");
        let second = decoder
            .decode(&received)
            .expect("second decode should succeed");

        assert!(
            first.stats.factor_cache_misses >= 1,
            "first decode should populate dense-factor cache"
        );
        assert!(
            second.stats.factor_cache_hits >= 1,
            "second decode should hit dense-factor cache"
        );
        assert_eq!(
            first.stats.factor_cache_last_reason,
            Some("cache_miss_rebuild")
        );
        assert_eq!(
            second.stats.factor_cache_last_reason,
            Some("signature_match_reuse")
        );
        assert_eq!(first.stats.factor_cache_last_reuse_eligible, Some(false));
        assert_eq!(second.stats.factor_cache_last_reuse_eligible, Some(true));
        assert_eq!(
            first.stats.factor_cache_last_key, second.stats.factor_cache_last_key,
            "repeated burst decode should probe the same structural cache key",
        );
        assert_eq!(
            second.stats.factor_cache_capacity,
            DENSE_FACTOR_CACHE_CAPACITY
        );
        assert!(
            second.stats.factor_cache_entries <= second.stats.factor_cache_capacity,
            "cache occupancy must remain bounded by configured capacity"
        );
    }

    #[test]
    fn decode_burst_loss_payload_recovers_with_repair_overhead() {
        let k = 8;
        let symbol_size = 32;
        let seed = 2026u64;

        let source = make_source_data(k, symbol_size);
        let encoder = SystematicEncoder::new(&source, symbol_size, seed).unwrap();
        let decoder = InactivationDecoder::new(k, symbol_size, seed);
        let l = decoder.params().l;

        let mut payload = make_received_source(&decoder, &source);
        for esi in (k as u32)..((k + l + 8) as u32) {
            let (cols, coefs) = decoder.repair_equation(esi);
            let repair_data = encoder.repair_symbol(esi);
            payload.push(ReceivedSymbol::repair(esi, cols, coefs, repair_data));
        }

        // Deterministic contiguous burst drop in payload symbols.
        payload.drain(3..7);

        let mut received = decoder.constraint_symbols();
        received.extend(payload);
        assert!(
            received.len() >= l,
            "burst-loss scenario must still provide at least L equations"
        );

        let first = decoder
            .decode(&received)
            .expect("burst-loss decode should recover source symbols");
        let second = InactivationDecoder::new(k, symbol_size, seed)
            .decode(&received)
            .expect("burst-loss replay decode should recover source symbols");

        assert_eq!(first.source, source);
        assert_eq!(second.source, source);
        assert_eq!(
            first.source, second.source,
            "replay should be deterministic"
        );
        assert_eq!(first.stats.peeled, second.stats.peeled);
        assert_eq!(first.stats.inactivated, second.stats.inactivated);
    }

    #[test]
    fn decode_corrupted_repair_symbol_reports_corrupt_output() {
        let k = 8;
        let symbol_size = 32;
        let seed = 42u64;

        let source = make_source_data(k, symbol_size);
        let encoder = SystematicEncoder::new(&source, symbol_size, seed).unwrap();
        let decoder = InactivationDecoder::new(k, symbol_size, seed);
        let l = decoder.params().l;

        let mut received = decoder.constraint_symbols();
        received.extend(make_received_source(&decoder, &source));
        let repair_start_idx = received.len();
        for esi in (k as u32)..(l as u32) {
            let (cols, coefs) = decoder.repair_equation(esi);
            let repair_data = encoder.repair_symbol(esi);
            received.push(ReceivedSymbol::repair(esi, cols, coefs, repair_data));
        }

        // Sanity: uncorrupted decode must succeed.
        decoder
            .decode(&received)
            .expect("uncorrupted decode must succeed");

        // Tamper the first actual repair symbol (not a constraint).
        // Constraint symbols come first and their ESIs can overlap with
        // repair ESIs, so index directly into the repair portion.
        received[repair_start_idx].data[0] ^= 0x5A;

        let err = decoder
            .decode(&received)
            .expect_err("corrupted repair symbol must cause decode failure");
        // Corruption can be detected via two paths depending on how the
        // corrupted RHS propagates through peeling:
        //  1. SingularMatrix — build_dense_core_rows detects a non-zero RHS
        //     on a fully-solved equation (inconsistency), before Gaussian
        //     elimination even starts.
        //  2. CorruptDecodedOutput — the solve succeeds but verify_decoded_output
        //     catches the mismatch between received and reconstructed symbols.
        assert!(
            matches!(
                err,
                DecodeError::SingularMatrix { .. } | DecodeError::CorruptDecodedOutput { .. }
            ),
            "expected SingularMatrix or CorruptDecodedOutput, got {err:?}"
        );
    }

    #[test]
    fn decode_with_proof_corrupted_repair_symbol_reports_failure_reason() {
        let k = 8;
        let symbol_size = 32;
        let seed = 42u64;

        let source = make_source_data(k, symbol_size);
        let encoder = SystematicEncoder::new(&source, symbol_size, seed).unwrap();
        let decoder = InactivationDecoder::new(k, symbol_size, seed);
        let l = decoder.params().l;

        let mut received = decoder.constraint_symbols();
        received.extend(make_received_source(&decoder, &source));
        let repair_start_idx = received.len();
        for esi in (k as u32)..(l as u32) {
            let (cols, coefs) = decoder.repair_equation(esi);
            let repair_data = encoder.repair_symbol(esi);
            received.push(ReceivedSymbol::repair(esi, cols, coefs, repair_data));
        }

        // Tamper the first actual repair symbol (index past constraints + source).
        received[repair_start_idx].data[0] ^= 0xA5;

        let (err, proof) = decoder
            .decode_with_proof(&received, ObjectId::new_for_test(9090), 0)
            .expect_err("corrupted repair symbol should fail with proof witness");
        // Corruption can surface as SingularMatrix (RHS inconsistency during
        // build_dense_core_rows) or CorruptDecodedOutput (verification mismatch).
        assert!(
            matches!(
                err,
                DecodeError::SingularMatrix { .. } | DecodeError::CorruptDecodedOutput { .. }
            ),
            "expected SingularMatrix or CorruptDecodedOutput, got {err:?}"
        );
        assert!(matches!(
            proof.outcome,
            crate::raptorq::proof::ProofOutcome::Failure {
                reason: FailureReason::SingularMatrix { .. }
                    | FailureReason::CorruptDecodedOutput { .. }
            }
        ));
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

        let dropped = k.saturating_sub(received.len());
        let parameter_set = format!("k={k},symbol_size={symbol_size},dropped={dropped}");
        let log_json = emit_decoder_unit_log(
            "RQ-C-LOG-FAIL-INSUFFICIENT-001",
            seed,
            &parameter_set,
            "decode_failure",
            "rch exec -- cargo test -p asupersync --lib raptorq::decoder::tests::decode_insufficient_symbols_fails -- --nocapture",
            None,
        );
        assert!(
            log_json.contains("\"scenario_id\":\"RQ-C-LOG-FAIL-INSUFFICIENT-001\""),
            "failure log must retain deterministic scenario id"
        );
        assert!(
            log_json
                .contains("\"artifact_path\":\"artifacts/raptorq_track_c_decoder_unit_v1.json\""),
            "failure log must include artifact pointer"
        );
    }

    #[test]
    fn decode_symbol_equation_arity_mismatch_fails() {
        let k = 8;
        let symbol_size = 32;
        let seed = 42u64;

        let source = make_source_data(k, symbol_size);
        let encoder = SystematicEncoder::new(&source, symbol_size, seed).unwrap();
        let decoder = InactivationDecoder::new(k, symbol_size, seed);
        let l = decoder.params().l;

        let mut received = decoder.constraint_symbols();
        received.extend(make_received_source(&decoder, &source));
        for esi in (k as u32)..(l as u32) {
            let (cols, coefs) = decoder.repair_equation(esi);
            let repair_data = encoder.repair_symbol(esi);
            received.push(ReceivedSymbol::repair(esi, cols, coefs, repair_data));
        }

        received[0].columns.push(0);
        let esi = received[0].esi;
        let columns = received[0].columns.len();
        let coefficients = received[0].coefficients.len();

        let err = decoder.decode(&received).unwrap_err();
        assert_eq!(
            err,
            DecodeError::SymbolEquationArityMismatch {
                esi,
                columns,
                coefficients
            }
        );
    }

    #[test]
    fn decode_with_proof_symbol_equation_arity_mismatch_reports_failure_reason() {
        let k = 8;
        let symbol_size = 32;
        let seed = 43u64;

        let source = make_source_data(k, symbol_size);
        let encoder = SystematicEncoder::new(&source, symbol_size, seed).unwrap();
        let decoder = InactivationDecoder::new(k, symbol_size, seed);
        let l = decoder.params().l;

        let mut received = decoder.constraint_symbols();
        received.extend(make_received_source(&decoder, &source));
        for esi in (k as u32)..(l as u32) {
            let (cols, coefs) = decoder.repair_equation(esi);
            let repair_data = encoder.repair_symbol(esi);
            received.push(ReceivedSymbol::repair(esi, cols, coefs, repair_data));
        }

        received[0].columns.push(0);
        let esi = received[0].esi;
        let columns = received[0].columns.len();
        let coefficients = received[0].coefficients.len();

        let (err, proof) = decoder
            .decode_with_proof(&received, ObjectId::new_for_test(4242), 0)
            .unwrap_err();
        assert_eq!(
            err,
            DecodeError::SymbolEquationArityMismatch {
                esi,
                columns,
                coefficients
            }
        );
        assert!(matches!(
            proof.outcome,
            crate::raptorq::proof::ProofOutcome::Failure {
                reason: FailureReason::SymbolEquationArityMismatch {
                    esi: e,
                    columns: c,
                    coefficients: coef_count
                }
            } if e == esi && c == columns && coef_count == coefficients
        ));
    }

    #[test]
    fn decode_column_index_out_of_range_fails_unrecoverably() {
        let k = 8;
        let symbol_size = 32;
        let seed = 44u64;

        let source = make_source_data(k, symbol_size);
        let encoder = SystematicEncoder::new(&source, symbol_size, seed).unwrap();
        let decoder = InactivationDecoder::new(k, symbol_size, seed);
        let l = decoder.params().l;

        let mut received = decoder.constraint_symbols();
        received.extend(make_received_source(&decoder, &source));
        for esi in (k as u32)..(l as u32) {
            let (cols, coefs) = decoder.repair_equation(esi);
            let repair_data = encoder.repair_symbol(esi);
            received.push(ReceivedSymbol::repair(esi, cols, coefs, repair_data));
        }

        let esi = received[0].esi;
        let invalid_column = l;
        received[0].columns[0] = invalid_column;

        let err = decoder.decode(&received).unwrap_err();
        assert_eq!(
            err,
            DecodeError::ColumnIndexOutOfRange {
                esi,
                column: invalid_column,
                max_valid: l
            }
        );
        assert!(err.is_unrecoverable());
        assert!(!err.is_recoverable());
    }

    #[test]
    fn decode_with_proof_column_index_out_of_range_reports_failure_reason() {
        let k = 8;
        let symbol_size = 32;
        let seed = 45u64;

        let source = make_source_data(k, symbol_size);
        let encoder = SystematicEncoder::new(&source, symbol_size, seed).unwrap();
        let decoder = InactivationDecoder::new(k, symbol_size, seed);
        let l = decoder.params().l;

        let mut received = decoder.constraint_symbols();
        received.extend(make_received_source(&decoder, &source));
        for esi in (k as u32)..(l as u32) {
            let (cols, coefs) = decoder.repair_equation(esi);
            let repair_data = encoder.repair_symbol(esi);
            received.push(ReceivedSymbol::repair(esi, cols, coefs, repair_data));
        }

        let esi = received[1].esi;
        let invalid_column = l + 2;
        received[1].columns[0] = invalid_column;

        let (err, proof) = decoder
            .decode_with_proof(&received, ObjectId::new_for_test(5252), 0)
            .unwrap_err();
        assert_eq!(
            err,
            DecodeError::ColumnIndexOutOfRange {
                esi,
                column: invalid_column,
                max_valid: l
            }
        );
        assert!(matches!(
            proof.outcome,
            crate::raptorq::proof::ProofOutcome::Failure {
                reason: FailureReason::ColumnIndexOutOfRange {
                    esi: e,
                    column,
                    max_valid
                }
            } if e == esi && column == invalid_column && max_valid == l
        ));
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
        assert_eq!(
            result1.stats.peel_queue_pushes, result2.stats.peel_queue_pushes,
            "peel queue push accounting must be deterministic"
        );
        assert_eq!(
            result1.stats.peel_queue_pops, result2.stats.peel_queue_pops,
            "peel queue pop accounting must be deterministic"
        );
        assert_eq!(
            result1.stats.dense_core_rows, result2.stats.dense_core_rows,
            "dense-core row extraction must be deterministic"
        );
        assert_eq!(
            result1.stats.dense_core_cols, result2.stats.dense_core_cols,
            "dense-core column extraction must be deterministic"
        );

        let parameter_set = format!("k={k},symbol_size={symbol_size},dropped=0");
        let log_json = emit_decoder_unit_log(
            "RQ-C-LOG-SUCCESS-DET-001",
            seed,
            &parameter_set,
            "ok",
            "rch exec -- cargo test -p asupersync --lib raptorq::decoder::tests::decode_deterministic -- --nocapture",
            Some(to_unit_decode_stats(k, 0, &result1.stats)),
        );
        assert!(
            log_json.contains("\"outcome\":\"ok\""),
            "success log should preserve deterministic outcome marker"
        );
        assert!(
            log_json.contains("\"repro_command\":\"rch exec --"),
            "success log must keep remote replay command"
        );
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
        assert!(
            result.stats.peel_queue_pushes >= result.stats.peel_queue_pops,
            "queue pushes should dominate or equal pops"
        );
        assert!(
            result.stats.peel_frontier_peak > 0,
            "peeling queue should observe non-zero frontier depth"
        );
        if result.stats.inactivated > 0 {
            assert!(
                result.stats.dense_core_cols > 0,
                "dense core should contain unsolved columns when inactivation occurs"
            );
            assert_eq!(
                result.stats.peeling_fallback_reason,
                Some("peeling_exhausted_to_dense_core"),
                "fallback reason should be explicit when we transition to dense core"
            );
        }
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

    #[test]
    fn verify_decoded_output_detects_corruption_witness() {
        let k = 6;
        let symbol_size = 16;
        let seed = 46u64;
        let decoder = InactivationDecoder::new(k, symbol_size, seed);
        let source = make_source_data(k, symbol_size);
        let received = make_received_source(&decoder, &source);

        let mut intermediate = vec![vec![0u8; symbol_size]; decoder.params().l];
        for (idx, src) in source.iter().enumerate() {
            intermediate[idx] = src.clone();
        }
        intermediate[0][0] ^= 0xA5;

        let err = decoder
            .verify_decoded_output(&received, &intermediate)
            .expect_err("corruption guard should reject inconsistent reconstruction");
        assert!(matches!(
            err,
            DecodeError::CorruptDecodedOutput {
                esi: 0,
                byte_index: 0,
                ..
            }
        ));
        assert!(err.is_unrecoverable());
    }

    #[test]
    fn failure_classification_is_explicit() {
        assert!(
            DecodeError::InsufficientSymbols {
                received: 1,
                required: 2
            }
            .is_recoverable()
        );
        assert!(DecodeError::SingularMatrix { row: 3 }.is_recoverable());
        assert!(
            DecodeError::SymbolSizeMismatch {
                expected: 8,
                actual: 7
            }
            .is_unrecoverable()
        );
        assert!(
            DecodeError::ColumnIndexOutOfRange {
                esi: 1,
                column: 99,
                max_valid: 12
            }
            .is_unrecoverable()
        );
        assert!(
            DecodeError::CorruptDecodedOutput {
                esi: 1,
                byte_index: 0,
                expected: 1,
                actual: 2
            }
            .is_unrecoverable()
        );
    }

    fn make_rank_deficient_state(
        params: &SystematicParams,
        symbol_size: usize,
        left_col: usize,
        right_col: usize,
    ) -> DecoderState {
        let equation = Equation::new(vec![left_col, right_col], vec![Gf256::ONE, Gf256::ONE]);
        let active_cols = [left_col, right_col].into_iter().collect();
        DecoderState {
            params: params.clone(),
            equations: vec![equation.clone(), equation],
            rhs: vec![vec![0x11; symbol_size], vec![0x22; symbol_size]],
            solved: vec![None; params.l],
            active_cols,
            inactive_cols: BTreeSet::new(),
            stats: DecodeStats::default(),
        }
    }

    fn make_pivot_tie_break_state(
        params: &SystematicParams,
        symbol_size: usize,
        left_col: usize,
        right_col: usize,
    ) -> DecoderState {
        let eq_left = Equation::new(vec![left_col], vec![Gf256::ONE]);
        let eq_mix = Equation::new(vec![left_col, right_col], vec![Gf256::ONE, Gf256::ONE]);
        let eq_right = Equation::new(vec![right_col], vec![Gf256::ONE]);
        let active_cols = [left_col, right_col].into_iter().collect();
        DecoderState {
            params: params.clone(),
            equations: vec![eq_left, eq_mix, eq_right],
            rhs: vec![
                vec![0x10; symbol_size],
                vec![0x30; symbol_size],
                vec![0x20; symbol_size],
            ],
            solved: vec![None; params.l],
            active_cols,
            inactive_cols: BTreeSet::new(),
            stats: DecodeStats::default(),
        }
    }

    fn make_inconsistent_overdetermined_state(
        params: &SystematicParams,
        symbol_size: usize,
        left_col: usize,
        right_col: usize,
    ) -> DecoderState {
        let eq_left = Equation::new(vec![left_col], vec![Gf256::ONE]);
        let eq_right = Equation::new(vec![right_col], vec![Gf256::ONE]);
        let eq_mix = Equation::new(vec![left_col, right_col], vec![Gf256::ONE, Gf256::ONE]);
        let active_cols = [left_col, right_col].into_iter().collect();
        DecoderState {
            params: params.clone(),
            equations: vec![eq_left, eq_right, eq_mix],
            rhs: vec![
                vec![0x10; symbol_size],
                vec![0x20; symbol_size],
                vec![0x31; symbol_size], // 0x10 ^ 0x20 = 0x30 => contradiction
            ],
            solved: vec![None; params.l],
            active_cols,
            inactive_cols: BTreeSet::new(),
            stats: DecodeStats::default(),
        }
    }

    fn make_dense_core_prunable_state(
        params: &SystematicParams,
        symbol_size: usize,
        left_col: usize,
        right_col: usize,
        empty_rhs_byte: u8,
    ) -> DecoderState {
        let eq_left = Equation::new(vec![left_col], vec![Gf256::ONE]);
        let eq_right = Equation::new(vec![right_col], vec![Gf256::ONE]);
        let eq_empty = Equation {
            terms: Vec::new(),
            used: false,
        };
        let active_cols = [left_col, right_col].into_iter().collect();
        DecoderState {
            params: params.clone(),
            equations: vec![eq_left, eq_right, eq_empty],
            rhs: vec![
                vec![0x10; symbol_size],
                vec![0x20; symbol_size],
                vec![empty_rhs_byte; symbol_size],
            ],
            solved: vec![None; params.l],
            active_cols,
            inactive_cols: BTreeSet::new(),
            stats: DecodeStats::default(),
        }
    }

    fn make_hard_regime_dense_state(
        params: &SystematicParams,
        symbol_size: usize,
        start_col: usize,
        width: usize,
    ) -> DecoderState {
        let cols: Vec<usize> = (start_col..start_col + width).collect();
        let mut equations = Vec::with_capacity(width);
        let mut rhs = Vec::with_capacity(width);

        // Upper-triangular dense system:
        // row i references cols[i..], so the matrix is full-rank while still dense.
        for i in 0..width {
            let row_cols = cols[i..].to_vec();
            let row_coefs = vec![Gf256::ONE; row_cols.len()];
            equations.push(Equation::new(row_cols, row_coefs));
            rhs.push(vec![(i as u8) + 1; symbol_size]);
        }

        DecoderState {
            params: params.clone(),
            equations,
            rhs,
            solved: vec![None; params.l],
            active_cols: cols.into_iter().collect(),
            inactive_cols: BTreeSet::new(),
            stats: DecodeStats::default(),
        }
    }

    fn make_block_schur_rank_deficient_state(
        params: &SystematicParams,
        symbol_size: usize,
        start_col: usize,
        width: usize,
    ) -> DecoderState {
        let cols: Vec<usize> = (start_col..start_col + width).collect();
        let mut equations = Vec::with_capacity(width);
        let mut rhs = Vec::with_capacity(width);

        for i in 0..width {
            equations.push(Equation::new(cols.clone(), vec![Gf256::ONE; cols.len()]));
            rhs.push(vec![(i as u8) + 1; symbol_size]);
        }

        DecoderState {
            params: params.clone(),
            equations,
            rhs,
            solved: vec![None; params.l],
            active_cols: cols.into_iter().collect(),
            inactive_cols: BTreeSet::new(),
            stats: DecodeStats::default(),
        }
    }

    #[test]
    fn singular_matrix_reports_original_column_id() {
        let decoder = InactivationDecoder::new(8, 16, 123);
        let params = decoder.params().clone();
        let mut state = make_rank_deficient_state(&params, 16, 3, 7);

        let err = decoder.inactivate_and_solve(&mut state).unwrap_err();
        assert_eq!(
            err,
            DecodeError::SingularMatrix { row: 7 },
            "rank-deficient failure should report original unsolved column id"
        );
    }

    #[test]
    fn singular_matrix_with_proof_keeps_deterministic_attempt_history() {
        let decoder = InactivationDecoder::new(8, 16, 321);
        let params = decoder.params().clone();
        let mut state = make_rank_deficient_state(&params, 16, 3, 7);
        let mut trace = EliminationTrace::default();

        let err = decoder
            .inactivate_and_solve_with_proof(&mut state, &mut trace)
            .unwrap_err();
        assert_eq!(err, DecodeError::SingularMatrix { row: 7 });
        assert_eq!(
            trace
                .pivot_events
                .iter()
                .map(|ev| ev.col)
                .collect::<Vec<_>>(),
            vec![3],
            "pivot history should be deterministic across rank-deficient failure"
        );
    }

    #[test]
    fn failure_reason_captures_attempted_pivot_columns() {
        let mut elimination = EliminationTrace::default();
        elimination.record_pivot(3, 0);
        elimination.record_pivot(9, 1);

        let reason =
            failure_reason_with_trace(&DecodeError::SingularMatrix { row: 11 }, &elimination);
        assert_eq!(
            reason,
            FailureReason::SingularMatrix {
                row: 11,
                attempted_cols: vec![3, 9],
            }
        );
    }

    #[test]
    fn pivot_tie_break_prefers_lowest_available_row_deterministically() {
        let decoder = InactivationDecoder::new(8, 1, 999);
        let params = decoder.params().clone();

        let mut state_one = make_pivot_tie_break_state(&params, 1, 3, 7);
        let mut trace_one = EliminationTrace::default();
        decoder
            .inactivate_and_solve_with_proof(&mut state_one, &mut trace_one)
            .expect("tie-break test state should be solvable");

        assert_eq!(
            trace_one
                .pivot_events
                .iter()
                .map(|ev| (ev.col, ev.row))
                .collect::<Vec<_>>(),
            vec![(3, 0), (7, 1)],
            "pivot order should be deterministic and prefer lowest available row"
        );
        assert_eq!(state_one.solved[3], Some(vec![0x10]));
        assert_eq!(state_one.solved[7], Some(vec![0x20]));

        let mut state_two = make_pivot_tie_break_state(&params, 1, 3, 7);
        let mut trace_two = EliminationTrace::default();
        decoder
            .inactivate_and_solve_with_proof(&mut state_two, &mut trace_two)
            .expect("second solve should match first solve");

        assert_eq!(
            trace_one.pivot_events, trace_two.pivot_events,
            "pivot trace should be stable across repeated runs"
        );
    }

    #[test]
    fn inconsistent_overdetermined_system_reports_singular_error() {
        let decoder = InactivationDecoder::new(8, 16, 111);
        let params = decoder.params().clone();
        let mut state = make_inconsistent_overdetermined_state(&params, 16, 3, 7);

        let err = decoder.inactivate_and_solve(&mut state).unwrap_err();
        assert_eq!(
            err,
            DecodeError::SingularMatrix { row: 2 },
            "contradictory overdetermined system should fail deterministically at witness row"
        );
    }

    #[test]
    fn inconsistent_overdetermined_with_proof_preserves_attempt_history() {
        let decoder = InactivationDecoder::new(8, 16, 222);
        let params = decoder.params().clone();
        let mut state = make_inconsistent_overdetermined_state(&params, 16, 3, 7);
        let mut trace = EliminationTrace::default();

        let err = decoder
            .inactivate_and_solve_with_proof(&mut state, &mut trace)
            .unwrap_err();
        assert_eq!(err, DecodeError::SingularMatrix { row: 2 });
        assert_eq!(
            trace
                .pivot_events
                .iter()
                .map(|ev| ev.col)
                .collect::<Vec<_>>(),
            vec![3, 7],
            "inconsistent-system witness should preserve full pivot-attempt history"
        );
    }

    #[test]
    fn dense_core_extraction_drops_redundant_zero_rows() {
        let decoder = InactivationDecoder::new(8, 16, 6060);
        let params = decoder.params().clone();
        let mut state = make_dense_core_prunable_state(&params, 16, 3, 7, 0x00);

        decoder
            .inactivate_and_solve(&mut state)
            .expect("state with redundant zero row should be solvable");
        assert_eq!(
            state.stats.dense_core_rows, 2,
            "dense core should only include rows with unsolved-column signal"
        );
        assert_eq!(
            state.stats.dense_core_cols, 2,
            "dense core should preserve unsolved column width"
        );
        assert_eq!(
            state.stats.dense_core_dropped_rows, 1,
            "one redundant zero-information row should be dropped"
        );
    }

    #[test]
    fn dense_core_inconsistent_constant_row_reports_equation_witness() {
        let decoder = InactivationDecoder::new(8, 16, 6161);
        let params = decoder.params().clone();
        let mut state = make_dense_core_prunable_state(&params, 16, 3, 7, 0x01);

        let err = decoder.inactivate_and_solve(&mut state).unwrap_err();
        assert_eq!(
            err,
            DecodeError::SingularMatrix { row: 2 },
            "inconsistent constant row should report deterministic original equation index"
        );
    }

    #[test]
    fn baseline_failure_triggers_deterministic_hard_regime_fallback() {
        let decoder = InactivationDecoder::new(8, 1, 4242);
        let params = decoder.params().clone();
        let mut state = make_rank_deficient_state(&params, 1, 3, 7);

        let err = decoder.inactivate_and_solve(&mut state).unwrap_err();
        assert_eq!(err, DecodeError::SingularMatrix { row: 7 });
        assert!(
            state.stats.hard_regime_activated,
            "fallback should activate hard regime deterministically"
        );
        assert_eq!(
            state.stats.hard_regime_fallbacks, 1,
            "exactly one fallback transition is expected"
        );
        assert!(
            state.stats.markowitz_pivots <= state.stats.pivots_selected,
            "hard-regime pivot accounting should remain internally consistent"
        );
    }

    #[test]
    fn proof_trace_records_fallback_transition_reason() {
        let decoder = InactivationDecoder::new(8, 1, 4343);
        let params = decoder.params().clone();
        let mut state = make_rank_deficient_state(&params, 1, 3, 7);
        let mut trace = EliminationTrace::default();

        let err = decoder
            .inactivate_and_solve_with_proof(&mut state, &mut trace)
            .unwrap_err();
        assert_eq!(err, DecodeError::SingularMatrix { row: 7 });
        assert_eq!(
            trace.strategy,
            InactivationStrategy::HighSupportFirst,
            "proof trace should expose fallback strategy"
        );
        assert_eq!(
            trace.strategy_transitions.len(),
            1,
            "fallback should record one strategy transition"
        );
        assert_eq!(
            trace.strategy_transitions[0].reason, "fallback_after_baseline_failure",
            "transition reason should be deterministic and triage-friendly"
        );
        assert_eq!(
            trace
                .pivot_events
                .iter()
                .map(|ev| ev.col)
                .collect::<Vec<_>>(),
            vec![3],
            "fallback proof should preserve the deterministic pivot-attempt witness"
        );
    }

    #[test]
    fn hard_regime_activation_is_deterministic_and_observable() {
        let decoder = InactivationDecoder::new(32, 1, 77);
        let params = decoder.params().clone();

        let mut state_one = make_hard_regime_dense_state(&params, 1, 4, 8);
        let mut trace_one = EliminationTrace::default();
        decoder
            .inactivate_and_solve_with_proof(&mut state_one, &mut trace_one)
            .expect("hard regime state should be solvable");

        assert!(
            state_one.stats.hard_regime_activated,
            "hard-regime transition should be observable in decode stats"
        );
        assert_eq!(
            state_one.stats.markowitz_pivots, 8,
            "all hard-regime pivots should use deterministic Markowitz selector"
        );
        assert_eq!(
            trace_one.strategy,
            InactivationStrategy::HighSupportFirst,
            "proof trace must expose hard-regime strategy"
        );
        assert_eq!(
            trace_one.strategy_transitions.len(),
            1,
            "hard regime should record a single strategy transition"
        );
        assert_eq!(
            trace_one.strategy_transitions[0].reason, "dense_or_near_square",
            "transition reason should be deterministic and triage-friendly"
        );

        let mut state_two = make_hard_regime_dense_state(&params, 1, 4, 8);
        let mut trace_two = EliminationTrace::default();
        decoder
            .inactivate_and_solve_with_proof(&mut state_two, &mut trace_two)
            .expect("repeated hard regime solve should succeed");

        assert_eq!(
            state_one.stats.markowitz_pivots, state_two.stats.markowitz_pivots,
            "hard-regime pivot counts should be stable across runs"
        );
        assert_eq!(
            trace_one.pivot_events, trace_two.pivot_events,
            "hard-regime pivot event ordering must be deterministic"
        );
        assert_eq!(
            trace_one.strategy_transitions, trace_two.strategy_transitions,
            "hard-regime strategy transition history must be deterministic"
        );
    }

    #[test]
    fn hard_regime_plan_selects_block_schur_for_dense_large_core() {
        let n_rows = 12;
        let n_cols = 12;
        let dense = vec![Gf256::ONE; n_rows * n_cols];
        let plan = select_hard_regime_plan(n_rows, n_cols, &dense);
        assert_eq!(
            plan,
            HardRegimePlan::BlockSchurLowRank { split_col: 8 },
            "dense 12x12 system should select deterministic block-schur plan"
        );
    }

    #[test]
    fn block_schur_failure_falls_back_to_markowitz_with_reason() {
        let decoder = InactivationDecoder::new(32, 1, 7070);
        let params = decoder.params().clone();
        let mut state = make_block_schur_rank_deficient_state(&params, 1, 4, 12);
        let mut trace = EliminationTrace::default();

        let err = decoder
            .inactivate_and_solve_with_proof(&mut state, &mut trace)
            .expect_err("rank-deficient block-schur candidate should fail deterministically");
        assert!(matches!(err, DecodeError::SingularMatrix { .. }));
        assert!(
            state.stats.hard_regime_activated,
            "dense rank-deficient system should activate hard regime"
        );
        assert_eq!(
            state.stats.hard_regime_branch,
            Some("block_schur_low_rank"),
            "stats should expose deterministic accelerated branch selection"
        );
        assert_eq!(
            state.stats.hard_regime_conservative_fallback_reason,
            Some("block_schur_failed_to_converge"),
            "stats should expose deterministic conservative fallback reason"
        );
        assert_eq!(
            state.stats.hard_regime_fallbacks, 1,
            "block-schur attempt should perform exactly one conservative fallback"
        );
        assert!(
            trace.strategy_transitions.iter().any(|transition| {
                transition.from == InactivationStrategy::BlockSchurLowRank
                    && transition.to == InactivationStrategy::HighSupportFirst
                    && transition.reason == "block_schur_failed_to_converge"
            }),
            "proof trace should record deterministic branch fallback transition"
        );
    }

    #[test]
    fn normal_regime_keeps_basic_pivot_strategy() {
        let decoder = InactivationDecoder::new(8, 1, 99);
        let params = decoder.params().clone();
        let mut state = make_pivot_tie_break_state(&params, 1, 3, 7);

        decoder
            .inactivate_and_solve(&mut state)
            .expect("normal regime test state should solve");

        assert!(
            !state.stats.hard_regime_activated,
            "small systems should stay on the baseline inactivation strategy"
        );
        assert_eq!(
            state.stats.markowitz_pivots, 0,
            "baseline strategy should not report Markowitz pivots"
        );
    }

    #[test]
    fn normal_regime_proof_trace_keeps_all_at_once_strategy() {
        let decoder = InactivationDecoder::new(8, 1, 100);
        let params = decoder.params().clone();
        let mut state = make_pivot_tie_break_state(&params, 1, 3, 7);
        let mut trace = EliminationTrace::default();

        decoder
            .inactivate_and_solve_with_proof(&mut state, &mut trace)
            .expect("normal regime proof solve should succeed");

        assert_eq!(
            trace.strategy,
            InactivationStrategy::AllAtOnce,
            "normal regime should stay on baseline strategy"
        );
        assert!(
            trace.strategy_transitions.is_empty(),
            "normal regime must not emit strategy transitions"
        );
    }

    #[test]
    fn policy_metadata_is_recorded_for_conservative_mode() {
        let decoder = InactivationDecoder::new(8, 1, 101);
        let params = decoder.params().clone();
        let mut state = make_pivot_tie_break_state(&params, 1, 3, 7);

        decoder
            .inactivate_and_solve(&mut state)
            .expect("conservative-mode state should solve");

        assert_eq!(state.stats.policy_mode, Some("conservative_baseline"));
        assert_eq!(
            state.stats.policy_reason,
            Some("expected_loss_conservative_gate")
        );
        assert_eq!(state.stats.policy_replay_ref, Some(POLICY_REPLAY_REF));
        assert!(state.stats.policy_baseline_loss > 0);
        assert!(state.stats.policy_high_support_loss > 0);
    }

    #[test]
    fn policy_metadata_is_recorded_for_aggressive_mode() {
        let decoder = InactivationDecoder::new(32, 1, 102);
        let params = decoder.params().clone();
        let mut state = make_hard_regime_dense_state(&params, 1, 4, 8);

        decoder
            .inactivate_and_solve(&mut state)
            .expect("aggressive-mode state should solve");

        assert!(
            matches!(
                state.stats.policy_mode,
                Some("high_support_first" | "block_schur_low_rank")
            ),
            "dense state should log an aggressive policy mode"
        );
        assert_eq!(state.stats.policy_reason, Some("expected_loss_minimum"));
        assert_eq!(state.stats.policy_replay_ref, Some(POLICY_REPLAY_REF));
        assert!(state.stats.policy_density_permille >= 350);
    }

    #[test]
    fn decoder_policy_budget_exhaustion_forces_conservative_baseline() {
        let n_rows = 65;
        let n_cols = 65;
        let dense = vec![Gf256::ONE; n_rows * n_cols];
        let decision = choose_runtime_decoder_policy(n_rows, n_cols, dense.len(), 0, 700);
        assert_eq!(decision.mode, DecoderPolicyMode::ConservativeBaseline);
        assert_eq!(decision.reason, "policy_budget_exhausted_conservative");
        assert!(decision.features.budget_exhausted);
    }

    #[test]
    fn decoder_policy_prefers_aggressive_strategy_for_dense_high_pressure() {
        let n_rows = 16;
        let n_cols = 16;
        let dense = vec![Gf256::ONE; n_rows * n_cols];
        let decision = choose_runtime_decoder_policy(n_rows, n_cols, dense.len(), 0, 850);
        assert!(
            matches!(
                decision.mode,
                DecoderPolicyMode::HighSupportFirst | DecoderPolicyMode::BlockSchurLowRank
            ),
            "dense/high-pressure matrix should avoid conservative baseline"
        );
    }

    #[test]
    fn decoder_policy_prefers_conservative_for_sparse_low_pressure() {
        let n_rows = 24;
        let n_cols = 16;
        let mut sparse = vec![Gf256::ZERO; n_rows * n_cols];
        for idx in 0..n_cols {
            sparse[idx * n_cols + idx] = Gf256::ONE;
        }

        let one = choose_runtime_decoder_policy(n_rows, n_cols, n_cols, 0, 40);
        let two = choose_runtime_decoder_policy(n_rows, n_cols, n_cols, 0, 40);
        assert_eq!(one, two, "policy decision should be deterministic");
        assert_eq!(one.mode, DecoderPolicyMode::ConservativeBaseline);
        assert_eq!(one.reason, "expected_loss_conservative_gate");
    }

    // ── all_source_equations / source_equation coverage (br-3narc.2.7) ──

    #[test]
    fn all_source_equations_returns_identity_map() {
        let k = 8;
        let decoder = InactivationDecoder::new(k, 32, 42);
        let equations = decoder.all_source_equations();

        assert_eq!(equations.len(), k, "should return exactly K equations");
        for (i, (cols, coefs)) in equations.iter().enumerate() {
            assert_eq!(cols, &[i], "source equation {i} should map to column {i}");
            assert_eq!(
                coefs,
                &[Gf256::ONE],
                "source equation {i} should have unit coefficient"
            );
        }
    }

    #[test]
    fn source_equation_matches_all_source_equations() {
        let k = 12;
        let decoder = InactivationDecoder::new(k, 16, 99);
        let all = decoder.all_source_equations();

        for esi in 0..k as u32 {
            let single = decoder.source_equation(esi);
            assert_eq!(
                single, all[esi as usize],
                "source_equation({esi}) must match all_source_equations()[{esi}]"
            );
        }
    }

    #[test]
    #[should_panic(expected = "source ESI must be < K")]
    fn source_equation_panics_on_esi_ge_k() {
        let k = 4;
        let decoder = InactivationDecoder::new(k, 16, 42);
        let _ = decoder.source_equation(k as u32); // ESI == K should panic
    }

    // ── Duplicate ESI handling (br-3narc.2.7) ──

    #[test]
    #[allow(clippy::similar_names)]
    fn decode_with_duplicate_source_esi_produces_defined_outcome() {
        // Feeding the same ESI twice gives the decoder redundant equations.
        // It should either succeed (if the extra equation is linearly dependent)
        // or fail with SingularMatrix (if it introduces inconsistency).
        // It must NOT panic.
        let k = 8;
        let symbol_size = 32;
        let seed = 42u64;
        let source: Vec<Vec<u8>> = (0..k)
            .map(|i| {
                (0..symbol_size)
                    .map(|j| ((i * 37 + j * 13 + 7) % 256) as u8)
                    .collect()
            })
            .collect();

        let encoder = SystematicEncoder::new(&source, symbol_size, seed).unwrap();
        let decoder = InactivationDecoder::new(k, symbol_size, seed);
        let l = decoder.params().l;

        let mut received = decoder.constraint_symbols();
        // Add all source symbols
        for (i, data) in source.iter().enumerate() {
            received.push(ReceivedSymbol::source(i as u32, data.clone()));
        }
        // Duplicate: add source symbol 0 again
        received.push(ReceivedSymbol::source(0, source[0].clone()));

        // Add repair to reach L
        for esi in (k as u32)..(l as u32) {
            let (cols, coefs) = decoder.repair_equation(esi);
            let repair_data = encoder.repair_symbol(esi);
            received.push(ReceivedSymbol::repair(esi, cols, coefs, repair_data));
        }

        // Must not panic; outcome is either Ok or a well-formed error
        let result = decoder.decode(&received);
        match result {
            Ok(outcome) => {
                assert_eq!(
                    outcome.source, source,
                    "decode with duplicate ESI should recover correct source"
                );
            }
            Err(e) => {
                // SingularMatrix is acceptable if duplicate introduces linear dependence
                // that prevents pivot selection. But it must be a recognized error type.
                assert!(
                    matches!(
                        e,
                        DecodeError::SingularMatrix { .. }
                            | DecodeError::InsufficientSymbols { .. }
                    ),
                    "unexpected error type with duplicate ESI: {e:?}"
                );
            }
        }
    }

    // ── Zero-data source symbols (br-3narc.2.7) ──

    #[test]
    fn decode_all_zeros_source_data() {
        let k = 8;
        let symbol_size = 32;
        let seed = 42u64;

        let source: Vec<Vec<u8>> = (0..k).map(|_| vec![0u8; symbol_size]).collect();
        let encoder = SystematicEncoder::new(&source, symbol_size, seed).unwrap();
        let decoder = InactivationDecoder::new(k, symbol_size, seed);
        let l = decoder.params().l;

        let mut received = decoder.constraint_symbols();
        for (i, data) in source.iter().enumerate() {
            received.push(ReceivedSymbol::source(i as u32, data.clone()));
        }
        for esi in (k as u32)..(l as u32) {
            let (cols, coefs) = decoder.repair_equation(esi);
            let repair_data = encoder.repair_symbol(esi);
            received.push(ReceivedSymbol::repair(esi, cols, coefs, repair_data));
        }

        let result = decoder
            .decode(&received)
            .expect("all-zeros source should decode");
        assert_eq!(result.source, source, "decoded all-zeros must match");
    }

    // ── Intermediate symbol reconstruction invariant (br-3narc.2.7) ──

    #[test]
    fn intermediate_symbols_match_encoder_after_decode() {
        let k = 8;
        let symbol_size = 32;
        let seed = 42u64;

        let source: Vec<Vec<u8>> = (0..k)
            .map(|i| {
                (0..symbol_size)
                    .map(|j| ((i * 37 + j * 13 + 7) % 256) as u8)
                    .collect()
            })
            .collect();

        let encoder = SystematicEncoder::new(&source, symbol_size, seed).unwrap();
        let decoder = InactivationDecoder::new(k, symbol_size, seed);
        let l = decoder.params().l;

        let mut received = decoder.constraint_symbols();
        for (i, data) in source.iter().enumerate() {
            received.push(ReceivedSymbol::source(i as u32, data.clone()));
        }
        for esi in (k as u32)..(l as u32) {
            let (cols, coefs) = decoder.repair_equation(esi);
            let repair_data = encoder.repair_symbol(esi);
            received.push(ReceivedSymbol::repair(esi, cols, coefs, repair_data));
        }

        let result = decoder.decode(&received).expect("decode should succeed");

        // Every intermediate symbol from decode must match the encoder's
        assert_eq!(result.intermediate.len(), l);
        for i in 0..l {
            assert_eq!(
                result.intermediate[i],
                encoder.intermediate_symbol(i),
                "intermediate symbol {i}/{l} must match encoder"
            );
        }
    }

    // ── Peeling + Gaussian coverage invariant (br-3narc.2.7) ──

    #[test]
    fn stats_peeled_plus_inactivated_covers_all_columns() {
        let k = 8;
        let symbol_size = 32;
        let seed = 42u64;

        let source: Vec<Vec<u8>> = (0..k)
            .map(|i| {
                (0..symbol_size)
                    .map(|j| ((i * 37 + j * 13 + 7) % 256) as u8)
                    .collect()
            })
            .collect();

        let encoder = SystematicEncoder::new(&source, symbol_size, seed).unwrap();
        let decoder = InactivationDecoder::new(k, symbol_size, seed);
        let l = decoder.params().l;

        let mut received = decoder.constraint_symbols();
        for (i, data) in source.iter().enumerate() {
            received.push(ReceivedSymbol::source(i as u32, data.clone()));
        }
        for esi in (k as u32)..(l as u32) {
            let (cols, coefs) = decoder.repair_equation(esi);
            let repair_data = encoder.repair_symbol(esi);
            received.push(ReceivedSymbol::repair(esi, cols, coefs, repair_data));
        }

        let result = decoder.decode(&received).expect("decode should succeed");
        assert_eq!(
            result.stats.peeled + result.stats.inactivated,
            l,
            "peeled + inactivated must equal L ({l})"
        );
    }

    // ── F6: Regime-shift detector unit tests ──

    fn make_regime_observation(
        density: usize,
        pressure: usize,
        success: bool,
    ) -> RegimeObservation {
        RegimeObservation {
            features: DecoderPolicyFeatures {
                density_permille: density,
                rank_deficit_permille: 0,
                inactivation_pressure_permille: pressure,
                overhead_ratio_permille: 0,
                budget_exhausted: false,
            },
            decode_success: success,
            policy_mode: DecoderPolicyMode::ConservativeBaseline,
        }
    }

    #[test]
    fn regime_detector_starts_stable_with_zero_deltas() {
        let detector = RegimeDetector::default();
        assert_eq!(detector.phase, RegimePhase::Stable);
        assert!(detector.current_deltas().is_zero());
        assert_eq!(detector.combined_score(), 0);
        assert!(!detector.baseline_established);
    }

    #[test]
    fn regime_detector_establishes_baseline_after_window_fills() {
        let mut detector = RegimeDetector::default();

        // Feed REGIME_WINDOW_CAPACITY observations with constant features.
        for _ in 0..REGIME_WINDOW_CAPACITY {
            detector.observe(make_regime_observation(200, 100, true));
        }

        assert!(
            detector.baseline_established,
            "baseline should be established after window fills"
        );
        assert_eq!(detector.baseline_density, 200);
        assert_eq!(detector.baseline_pressure, 100);
        assert_eq!(detector.phase, RegimePhase::Stable);
    }

    #[test]
    fn regime_detector_stays_stable_under_constant_workload() {
        let mut detector = RegimeDetector::default();

        // Fill window to establish baseline.
        for _ in 0..REGIME_WINDOW_CAPACITY {
            detector.observe(make_regime_observation(200, 100, true));
        }

        // Feed more constant observations.
        for _ in 0..REGIME_WINDOW_CAPACITY * 2 {
            let deltas = detector.observe(make_regime_observation(200, 100, true));
            assert!(
                deltas.is_zero(),
                "stable workload should produce zero deltas"
            );
        }

        assert_eq!(detector.phase, RegimePhase::Stable);
        assert_eq!(detector.retune_count, 0);
        assert_eq!(detector.rollback_count, 0);
    }

    #[test]
    fn regime_detector_detects_shift_on_large_drift() {
        let mut detector = RegimeDetector::default();

        // Establish baseline at low density/pressure.
        for _ in 0..REGIME_WINDOW_CAPACITY {
            detector.observe(make_regime_observation(100, 50, true));
        }
        assert!(detector.baseline_established);

        // Inject a large drift: density jumps from 100 to 800.
        // This should accumulate CUSUM score and eventually trigger a shift.
        let mut shifted = false;
        for _ in 0..REGIME_WINDOW_CAPACITY * 2 {
            detector.observe(make_regime_observation(800, 400, true));
            if detector.retune_count > 0 {
                shifted = true;
                break;
            }
        }

        assert!(
            shifted,
            "large drift should trigger at least one retuning event"
        );
        assert!(
            !detector.current_deltas().is_zero(),
            "retuning should produce non-zero deltas"
        );
    }

    #[test]
    fn regime_retuning_deltas_are_bounded() {
        let mut detector = RegimeDetector::default();

        // Establish baseline.
        for _ in 0..REGIME_WINDOW_CAPACITY {
            detector.observe(make_regime_observation(100, 50, true));
        }

        // Force a massive drift.
        for _ in 0..REGIME_WINDOW_CAPACITY * 3 {
            detector.observe(make_regime_observation(999, 999, true));
        }

        let deltas = detector.current_deltas();
        let cap = REGIME_MAX_RETUNE_DELTA;
        assert!(
            deltas.baseline_intercept_delta.abs() <= cap,
            "baseline intercept delta {} should be within [-{}, {}]",
            deltas.baseline_intercept_delta,
            cap,
            cap
        );
        assert!(
            deltas.density_bias_delta.abs() <= cap,
            "density bias delta {} should be within [-{}, {}]",
            deltas.density_bias_delta,
            cap,
            cap
        );
        assert!(
            deltas.pressure_bias_delta.abs() <= cap,
            "pressure bias delta {} should be within [-{}, {}]",
            deltas.pressure_bias_delta,
            cap,
            cap
        );
    }

    #[test]
    fn regime_detector_rolls_back_on_decode_failure_after_retuning() {
        let mut detector = RegimeDetector::default();

        // Establish baseline.
        for _ in 0..REGIME_WINDOW_CAPACITY {
            detector.observe(make_regime_observation(100, 50, true));
        }

        // Trigger a shift.
        for _ in 0..REGIME_WINDOW_CAPACITY * 2 {
            detector.observe(make_regime_observation(800, 400, true));
            if detector.retune_count > 0 {
                break;
            }
        }
        assert!(detector.retune_count > 0, "should have retuned");
        assert_eq!(detector.phase, RegimePhase::Retuned);

        // Now a decode failure should trigger rollback.
        detector.observe(make_regime_observation(800, 400, false));
        assert!(
            detector.current_deltas().is_zero(),
            "rollback should zero all deltas"
        );
        assert!(detector.rollback_count > 0, "rollback should be counted");
    }

    #[test]
    fn regime_detector_locks_conservative_after_oscillation_limit() {
        let mut detector = RegimeDetector::default();

        for cycle in 0..REGIME_ROLLBACK_OSCILLATION_LIMIT {
            // Establish baseline.
            detector.baseline_established = false;
            for _ in 0..REGIME_WINDOW_CAPACITY {
                detector.observe(make_regime_observation(100, 50, true));
            }

            // Trigger shift.
            for _ in 0..REGIME_WINDOW_CAPACITY * 2 {
                detector.observe(make_regime_observation(800, 400, true));
                if detector.retune_count > cycle {
                    break;
                }
            }

            // Trigger rollback.
            if detector.phase == RegimePhase::Retuned {
                detector.observe(make_regime_observation(800, 400, false));
            }
        }

        assert_eq!(
            detector.phase,
            RegimePhase::LockedConservative,
            "should lock to conservative after {REGIME_ROLLBACK_OSCILLATION_LIMIT} oscillations"
        );

        // Further observations should return zero deltas.
        let deltas = detector.observe(make_regime_observation(999, 999, true));
        assert!(
            deltas.is_zero(),
            "locked conservative should always return zero deltas"
        );
    }

    #[test]
    fn regime_detector_window_bounded_to_capacity() {
        let mut detector = RegimeDetector::default();

        // Feed more observations than window capacity.
        for _ in 0..(REGIME_WINDOW_CAPACITY * 3) {
            detector.observe(make_regime_observation(200, 100, true));
        }

        assert!(
            detector.window.len() <= REGIME_WINDOW_CAPACITY,
            "window should never exceed capacity: got {} vs max {}",
            detector.window.len(),
            REGIME_WINDOW_CAPACITY
        );
    }

    #[test]
    fn regime_detector_stats_applied_to_decode_stats() {
        let mut detector = RegimeDetector::default();
        for _ in 0..REGIME_WINDOW_CAPACITY {
            detector.observe(make_regime_observation(200, 100, true));
        }

        let mut stats = DecodeStats::default();
        detector.apply_to_stats(&mut stats);

        assert_eq!(stats.regime_state, Some(REGIME_STATE_STABLE));
        assert_eq!(stats.regime_replay_ref, Some(REGIME_REPLAY_REF));
        assert_eq!(stats.regime_retune_count, 0);
        assert_eq!(stats.regime_rollback_count, 0);
        assert_eq!(stats.regime_window_len, REGIME_WINDOW_CAPACITY);
    }

    #[test]
    fn regime_retuned_policy_losses_differ_from_static() {
        let features = DecoderPolicyFeatures {
            density_permille: 500,
            rank_deficit_permille: 100,
            inactivation_pressure_permille: 300,
            overhead_ratio_permille: 50,
            budget_exhausted: false,
        };
        let n_cols = 16;

        let (static_bl, static_hs, static_bs) = policy_losses(features, n_cols);
        let deltas = RetuningDeltas {
            baseline_intercept_delta: -100,
            density_bias_delta: -1,
            pressure_bias_delta: -1,
        };
        let (retuned_bl, retuned_hs, retuned_bs) =
            policy_losses_with_retuning(features, n_cols, deltas);

        assert!(
            retuned_bl < static_bl,
            "retuning with negative bias should lower baseline loss: {retuned_bl} vs {static_bl}"
        );
        // Aggressive modes should remain unchanged.
        assert_eq!(retuned_hs, static_hs);
        assert_eq!(retuned_bs, static_bs);
    }

    #[test]
    fn regime_retuned_policy_zero_deltas_matches_static() {
        let features = DecoderPolicyFeatures {
            density_permille: 400,
            rank_deficit_permille: 200,
            inactivation_pressure_permille: 150,
            overhead_ratio_permille: 80,
            budget_exhausted: false,
        };
        let n_cols = 20;

        let (static_bl, static_hs, static_bs) = policy_losses(features, n_cols);
        let (retuned_bl, retuned_hs, retuned_bs) =
            policy_losses_with_retuning(features, n_cols, RetuningDeltas::default());

        assert_eq!(static_bl, retuned_bl);
        assert_eq!(static_hs, retuned_hs);
        assert_eq!(static_bs, retuned_bs);
    }

    #[test]
    fn regime_detector_deterministic_replay() {
        // Two detectors fed identical sequences must produce identical state.
        let observations: Vec<RegimeObservation> = (0..REGIME_WINDOW_CAPACITY * 2)
            .map(|i| {
                let density = 100 + (i % 10) * 80;
                let pressure = 50 + (i % 7) * 60;
                make_regime_observation(density, pressure, i % 5 != 0)
            })
            .collect();

        let mut det_a = RegimeDetector::default();
        let mut det_b = RegimeDetector::default();

        for obs in &observations {
            let da = det_a.observe(*obs);
            let db = det_b.observe(*obs);
            assert_eq!(da, db, "deterministic replay violated at observation");
        }

        assert_eq!(det_a.combined_score(), det_b.combined_score());
        assert_eq!(det_a.phase, det_b.phase);
        assert_eq!(det_a.retune_count, det_b.retune_count);
        assert_eq!(det_a.rollback_count, det_b.rollback_count);
    }
}
