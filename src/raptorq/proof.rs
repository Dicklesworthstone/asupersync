//! RaptorQ decode proof artifact for explainable failures.
//!
//! This module provides a compact, deterministic artifact that explains
//! how a decode operation proceeded and why it succeeded or failed.
//!
//! # Design Goals
//!
//! 1. **Deterministic**: Same inputs produce identical artifacts
//! 2. **Bounded size**: Explicit caps on unbounded collections
//! 3. **Explainable**: Human-readable failure reasons
//! 4. **Replayable**: Sufficient info to reproduce decoder state transitions

use crate::raptorq::decoder::{DecodeError, InactivationDecoder, ReceivedSymbol};
use crate::types::ObjectId;
use crate::util::DetHasher;
use std::collections::BinaryHeap;
use std::fmt;

/// Maximum number of pivot events to record before truncation.
pub const MAX_PIVOT_EVENTS: usize = 256;

/// Maximum number of received symbol IDs to record.
pub const MAX_RECEIVED_SYMBOLS: usize = 1024;

/// Version of the proof artifact schema.
pub const PROOF_SCHEMA_VERSION: u8 = 1;

// ============================================================================
// Proof artifact types
// ============================================================================

/// A proof-carrying decode artifact that explains the decode process.
///
/// This artifact is produced during decoding and captures:
/// - Configuration and inputs
/// - Key decision points (pivots, inactivation)
/// - Final outcome with explanation
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodeProof {
    /// Schema version for forward compatibility.
    pub version: u8,
    /// Configuration used for decoding.
    pub config: DecodeConfig,
    /// Summary of received symbols.
    pub received: ReceivedSummary,
    /// Phase 1: Peeling events.
    pub peeling: PeelingTrace,
    /// Phase 2: Inactivation and elimination events.
    pub elimination: EliminationTrace,
    /// Final outcome.
    pub outcome: ProofOutcome,
}

impl DecodeProof {
    /// Create a new proof builder.
    #[must_use]
    pub fn builder(config: DecodeConfig) -> DecodeProofBuilder {
        DecodeProofBuilder::new(config)
    }

    /// Compute a deterministic hash of the proof for deduplication/verification.
    #[must_use]
    pub fn content_hash(&self) -> u64 {
        use std::hash::{Hash, Hasher};
        let mut hasher = DetHasher::default();
        self.version.hash(&mut hasher);
        self.config.hash(&mut hasher);
        self.received.hash(&mut hasher);
        self.peeling.hash(&mut hasher);
        self.elimination.hash(&mut hasher);
        self.outcome.hash(&mut hasher);
        hasher.finish()
    }

    /// Replay the decode with the provided symbols and verify the proof trace matches.
    ///
    /// Returns a detailed [`ReplayError`] if any divergence is detected.
    pub fn replay_and_verify(&self, symbols: &[ReceivedSymbol]) -> Result<(), ReplayError> {
        let decoder =
            InactivationDecoder::new(self.config.k, self.config.symbol_size, self.config.seed);
        let actual =
            match decoder.decode_with_proof(symbols, self.config.object_id, self.config.sbn) {
                Ok(result) => result.proof,
                Err((_err, proof)) => proof,
            };
        compare_proofs(self, &actual)
    }
}

// ============================================================================
// Replay verification
// ============================================================================

/// Detailed error for proof replay verification.
#[derive(Debug)]
pub enum ReplayError {
    /// Generic mismatch for scalar fields.
    Mismatch {
        /// Name of the mismatched field.
        field: &'static str,
        /// Expected value (formatted).
        expected: String,
        /// Actual value (formatted).
        actual: String,
    },
    /// Sequence mismatch at a specific index.
    SequenceMismatch {
        /// Name of the sequence being compared.
        label: &'static str,
        /// Index of the first mismatch.
        index: usize,
        /// Expected value at the mismatch (formatted).
        expected: String,
        /// Actual value at the mismatch (formatted).
        actual: String,
    },
}

impl fmt::Display for ReplayError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Mismatch {
                field,
                expected,
                actual,
            } => write!(f, "mismatch for {field}: expected {expected}, got {actual}"),
            Self::SequenceMismatch {
                label,
                index,
                expected,
                actual,
            } => write!(
                f,
                "sequence mismatch for {label} at index {index}: expected {expected}, got {actual}"
            ),
        }
    }
}

impl std::error::Error for ReplayError {}

fn mismatch<T: fmt::Debug>(field: &'static str, expected: T, actual: T) -> ReplayError {
    ReplayError::Mismatch {
        field,
        expected: format!("{expected:?}"),
        actual: format!("{actual:?}"),
    }
}

fn sequence_mismatch(
    label: &'static str,
    index: usize,
    expected: String,
    actual: String,
) -> ReplayError {
    ReplayError::SequenceMismatch {
        label,
        index,
        expected,
        actual,
    }
}

fn compare_prefix<T: PartialEq + fmt::Debug>(
    label: &'static str,
    expected: &[T],
    actual: &[T],
    truncated: bool,
) -> Result<(), ReplayError> {
    if actual.len() < expected.len() {
        return Err(sequence_mismatch(
            label,
            actual.len(),
            format!("{:?}", expected.get(actual.len())),
            "missing".to_string(),
        ));
    }
    for (idx, (exp, act)) in expected.iter().zip(actual.iter()).enumerate() {
        if exp != act {
            return Err(sequence_mismatch(
                label,
                idx,
                format!("{exp:?}"),
                format!("{act:?}"),
            ));
        }
    }
    if !truncated && actual.len() != expected.len() {
        return Err(mismatch(
            label,
            format!("len {}", expected.len()),
            format!("len {}", actual.len()),
        ));
    }
    Ok(())
}

#[allow(clippy::too_many_lines)]
fn compare_proofs(expected: &DecodeProof, actual: &DecodeProof) -> Result<(), ReplayError> {
    if expected.version != actual.version {
        return Err(mismatch("version", expected.version, actual.version));
    }
    if expected.config != actual.config {
        return Err(mismatch("config", &expected.config, &actual.config));
    }

    let exp_recv = &expected.received;
    let act_recv = &actual.received;
    if exp_recv.total != act_recv.total {
        return Err(mismatch("received.total", exp_recv.total, act_recv.total));
    }
    if exp_recv.source_count != act_recv.source_count {
        return Err(mismatch(
            "received.source_count",
            exp_recv.source_count,
            act_recv.source_count,
        ));
    }
    if exp_recv.repair_count != act_recv.repair_count {
        return Err(mismatch(
            "received.repair_count",
            exp_recv.repair_count,
            act_recv.repair_count,
        ));
    }
    if exp_recv.truncated != act_recv.truncated {
        return Err(mismatch(
            "received.truncated",
            exp_recv.truncated,
            act_recv.truncated,
        ));
    }
    compare_prefix(
        "received.esis",
        &exp_recv.esis,
        &act_recv.esis,
        exp_recv.truncated,
    )?;

    let exp_peel = &expected.peeling;
    let act_peel = &actual.peeling;
    if exp_peel.solved != act_peel.solved {
        return Err(mismatch("peeling.solved", exp_peel.solved, act_peel.solved));
    }
    if exp_peel.truncated != act_peel.truncated {
        return Err(mismatch(
            "peeling.truncated",
            exp_peel.truncated,
            act_peel.truncated,
        ));
    }
    compare_prefix(
        "peeling.solved_indices",
        &exp_peel.solved_indices,
        &act_peel.solved_indices,
        exp_peel.truncated,
    )?;

    let exp_elim = &expected.elimination;
    let act_elim = &actual.elimination;
    if exp_elim.inactivated != act_elim.inactivated {
        return Err(mismatch(
            "elimination.inactivated",
            exp_elim.inactivated,
            act_elim.inactivated,
        ));
    }
    if exp_elim.pivots != act_elim.pivots {
        return Err(mismatch(
            "elimination.pivots",
            exp_elim.pivots,
            act_elim.pivots,
        ));
    }
    if exp_elim.row_ops != act_elim.row_ops {
        return Err(mismatch(
            "elimination.row_ops",
            exp_elim.row_ops,
            act_elim.row_ops,
        ));
    }
    if exp_elim.truncated != act_elim.truncated {
        return Err(mismatch(
            "elimination.truncated",
            exp_elim.truncated,
            act_elim.truncated,
        ));
    }
    compare_prefix(
        "elimination.inactive_cols",
        &exp_elim.inactive_cols,
        &act_elim.inactive_cols,
        exp_elim.truncated,
    )?;
    compare_prefix(
        "elimination.pivot_events",
        &exp_elim.pivot_events,
        &act_elim.pivot_events,
        exp_elim.truncated,
    )?;

    if expected.outcome != actual.outcome {
        return Err(mismatch("outcome", &expected.outcome, &actual.outcome));
    }

    Ok(())
}

/// Decode configuration captured in the proof.
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct DecodeConfig {
    /// Object ID being decoded.
    pub object_id: ObjectId,
    /// Source block number.
    pub sbn: u8,
    /// Number of source symbols (K).
    pub k: usize,
    /// Number of LDPC symbols (S).
    pub s: usize,
    /// Number of HDPC symbols (H).
    pub h: usize,
    /// Total intermediate symbols (L = K + S + H).
    pub l: usize,
    /// Symbol size in bytes.
    pub symbol_size: usize,
    /// Seed used for encoding.
    pub seed: u64,
}

/// Summary of received symbols.
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct ReceivedSummary {
    /// Total symbols received.
    pub total: usize,
    /// Number of source symbols received.
    pub source_count: usize,
    /// Number of repair symbols received.
    pub repair_count: usize,
    /// ESIs of received symbols (sorted, truncated to MAX_RECEIVED_SYMBOLS).
    pub esis: Vec<u32>,
    /// True if ESI list was truncated.
    pub truncated: bool,
}

impl ReceivedSummary {
    /// Create from a list of (ESI, is_source) pairs.
    ///
    /// ESIs are recorded in deterministic ascending order and truncated
    /// to the smallest MAX_RECEIVED_SYMBOLS entries.
    #[must_use]
    pub fn from_received(symbols: impl Iterator<Item = (u32, bool)>) -> Self {
        let mut source_count = 0;
        let mut repair_count = 0;
        let mut total = 0usize;
        let mut esis_heap: BinaryHeap<u32> = BinaryHeap::new();

        for (esi, is_source) in symbols {
            total += 1;
            if is_source {
                source_count += 1;
            } else {
                repair_count += 1;
            }
            if esis_heap.len() < MAX_RECEIVED_SYMBOLS {
                esis_heap.push(esi);
                continue;
            }
            if let Some(&max) = esis_heap.peek() {
                if esi < max {
                    esis_heap.pop();
                    esis_heap.push(esi);
                }
            }
        }

        let truncated = total > MAX_RECEIVED_SYMBOLS;
        let mut esis = esis_heap.into_vec();
        esis.sort_unstable();
        Self {
            total,
            source_count,
            repair_count,
            esis,
            truncated,
        }
    }
}

/// Trace of peeling (belief propagation) phase.
#[derive(Debug, Clone, Default, Hash, PartialEq, Eq)]
pub struct PeelingTrace {
    /// Number of symbols solved via peeling.
    pub solved: usize,
    /// Intermediate symbol indices solved during peeling.
    pub solved_indices: Vec<usize>,
    /// True if solved_indices was truncated.
    pub truncated: bool,
}

impl PeelingTrace {
    /// Record a solved symbol index.
    pub fn record_solved(&mut self, col: usize) {
        self.solved += 1;
        if self.solved_indices.len() < MAX_PIVOT_EVENTS {
            self.solved_indices.push(col);
        } else {
            self.truncated = true;
        }
    }
}

/// Trace of inactivation and Gaussian elimination phase.
#[derive(Debug, Clone, Default, Hash, PartialEq, Eq)]
pub struct EliminationTrace {
    /// Number of columns marked as inactive.
    pub inactivated: usize,
    /// Column indices that were inactivated.
    pub inactive_cols: Vec<usize>,
    /// Number of pivot selections.
    pub pivots: usize,
    /// Pivot events: (column, pivot_row) pairs.
    pub pivot_events: Vec<PivotEvent>,
    /// Number of row operations performed.
    pub row_ops: usize,
    /// True if pivot_events was truncated.
    pub truncated: bool,
}

impl EliminationTrace {
    /// Record an inactivated column.
    pub fn record_inactivation(&mut self, col: usize) {
        self.inactivated += 1;
        if self.inactive_cols.len() < MAX_PIVOT_EVENTS {
            self.inactive_cols.push(col);
        }
    }

    /// Record a pivot selection.
    pub fn record_pivot(&mut self, col: usize, row: usize) {
        self.pivots += 1;
        if self.pivot_events.len() < MAX_PIVOT_EVENTS {
            self.pivot_events.push(PivotEvent { col, row });
        } else {
            self.truncated = true;
        }
    }

    /// Record a row operation.
    pub fn record_row_op(&mut self) {
        self.row_ops += 1;
    }
}

/// A single pivot selection event.
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct PivotEvent {
    /// Column being eliminated.
    pub col: usize,
    /// Row selected as pivot.
    pub row: usize,
}

/// Final decode outcome.
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub enum ProofOutcome {
    /// Decode succeeded.
    Success {
        /// Total symbols recovered.
        symbols_recovered: usize,
    },
    /// Decode failed with a specific reason.
    Failure {
        /// The error that occurred.
        reason: FailureReason,
    },
}

/// Detailed failure reason for proof artifact.
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub enum FailureReason {
    /// Not enough symbols received.
    InsufficientSymbols {
        /// Symbols received.
        received: usize,
        /// Symbols required.
        required: usize,
    },
    /// Matrix became singular during elimination.
    SingularMatrix {
        /// Row that couldn't find a pivot.
        row: usize,
        /// Columns that were attempted.
        attempted_cols: Vec<usize>,
    },
    /// Symbol size mismatch.
    SymbolSizeMismatch {
        /// Expected size.
        expected: usize,
        /// Actual size.
        actual: usize,
    },
    /// Received symbol has mismatched equation vectors.
    SymbolEquationArityMismatch {
        /// ESI of malformed symbol.
        esi: u32,
        /// Number of column indices.
        columns: usize,
        /// Number of coefficients.
        coefficients: usize,
    },
}

impl From<&DecodeError> for FailureReason {
    fn from(err: &DecodeError) -> Self {
        match err {
            DecodeError::InsufficientSymbols { received, required } => Self::InsufficientSymbols {
                received: *received,
                required: *required,
            },
            DecodeError::SingularMatrix { row } => Self::SingularMatrix {
                row: *row,
                attempted_cols: Vec::new(), // Filled in by caller if available
            },
            DecodeError::SymbolSizeMismatch { expected, actual } => Self::SymbolSizeMismatch {
                expected: *expected,
                actual: *actual,
            },
            DecodeError::SymbolEquationArityMismatch {
                esi,
                columns,
                coefficients,
            } => Self::SymbolEquationArityMismatch {
                esi: *esi,
                columns: *columns,
                coefficients: *coefficients,
            },
        }
    }
}

// ============================================================================
// Builder for incremental construction
// ============================================================================

/// Builder for constructing a decode proof incrementally.
#[derive(Debug)]
pub struct DecodeProofBuilder {
    config: DecodeConfig,
    received: Option<ReceivedSummary>,
    peeling: PeelingTrace,
    elimination: EliminationTrace,
    outcome: Option<ProofOutcome>,
}

impl DecodeProofBuilder {
    /// Create a new builder with the given configuration.
    #[must_use]
    pub fn new(config: DecodeConfig) -> Self {
        Self {
            config,
            received: None,
            peeling: PeelingTrace::default(),
            elimination: EliminationTrace::default(),
            outcome: None,
        }
    }

    /// Set the received symbols summary.
    pub fn set_received(&mut self, received: ReceivedSummary) {
        self.received = Some(received);
    }

    /// Get mutable access to the peeling trace.
    pub fn peeling_mut(&mut self) -> &mut PeelingTrace {
        &mut self.peeling
    }

    /// Get mutable access to the elimination trace.
    pub fn elimination_mut(&mut self) -> &mut EliminationTrace {
        &mut self.elimination
    }

    /// Mark decode as successful.
    pub fn set_success(&mut self, symbols_recovered: usize) {
        self.outcome = Some(ProofOutcome::Success { symbols_recovered });
    }

    /// Mark decode as failed.
    pub fn set_failure(&mut self, reason: FailureReason) {
        self.outcome = Some(ProofOutcome::Failure { reason });
    }

    /// Build the final proof artifact.
    ///
    /// # Panics
    ///
    /// Panics if received or outcome hasn't been set.
    #[must_use]
    pub fn build(self) -> DecodeProof {
        DecodeProof {
            version: PROOF_SCHEMA_VERSION,
            config: self.config,
            received: self.received.expect("received must be set before build"),
            peeling: self.peeling,
            elimination: self.elimination,
            outcome: self.outcome.expect("outcome must be set before build"),
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::raptorq::decoder::{InactivationDecoder, ReceivedSymbol};
    use crate::raptorq::systematic::SystematicEncoder;

    fn make_test_config() -> DecodeConfig {
        DecodeConfig {
            object_id: ObjectId::new(0, 1),
            sbn: 0,
            k: 10,
            s: 3,
            h: 2,
            l: 15,
            symbol_size: 64,
            seed: 42,
        }
    }

    #[test]
    fn proof_builder_success() {
        let config = make_test_config();
        let mut builder = DecodeProof::builder(config);

        builder.set_received(ReceivedSummary {
            total: 15,
            source_count: 10,
            repair_count: 5,
            esis: (0..15).collect(),
            truncated: false,
        });

        builder.peeling_mut().record_solved(0);
        builder.peeling_mut().record_solved(1);

        builder.elimination_mut().record_inactivation(2);
        builder.elimination_mut().record_pivot(2, 0);
        builder.elimination_mut().record_row_op();

        builder.set_success(10);

        let proof = builder.build();

        assert_eq!(proof.version, PROOF_SCHEMA_VERSION);
        assert_eq!(proof.peeling.solved, 2);
        assert_eq!(proof.elimination.pivots, 1);
        assert!(matches!(proof.outcome, ProofOutcome::Success { .. }));
    }

    #[test]
    fn proof_builder_failure() {
        let config = make_test_config();
        let mut builder = DecodeProof::builder(config);

        builder.set_received(ReceivedSummary {
            total: 5,
            source_count: 5,
            repair_count: 0,
            esis: (0..5).collect(),
            truncated: false,
        });

        builder.set_failure(FailureReason::InsufficientSymbols {
            received: 5,
            required: 15,
        });

        let proof = builder.build();

        assert!(matches!(
            proof.outcome,
            ProofOutcome::Failure {
                reason: FailureReason::InsufficientSymbols { .. }
            }
        ));
    }

    #[test]
    fn received_summary_truncation() {
        let symbols = (0..2000).map(|i| (i, i < 1000));
        let summary = ReceivedSummary::from_received(symbols);

        assert_eq!(summary.total, 2000);
        assert_eq!(summary.source_count, 1000);
        assert_eq!(summary.repair_count, 1000);
        assert_eq!(summary.esis.len(), MAX_RECEIVED_SYMBOLS);
        assert!(summary.truncated);
    }

    #[test]
    fn content_hash_deterministic() {
        let config = make_test_config();
        let mut builder1 = DecodeProof::builder(config.clone());
        let mut builder2 = DecodeProof::builder(config);

        for builder in [&mut builder1, &mut builder2] {
            builder.set_received(ReceivedSummary {
                total: 15,
                source_count: 10,
                repair_count: 5,
                esis: (0..15).collect(),
                truncated: false,
            });
            builder.set_success(10);
        }

        let proof1 = builder1.build();
        let proof2 = builder2.build();

        assert_eq!(proof1.content_hash(), proof2.content_hash());
    }

    #[test]
    fn replay_verification_roundtrip() {
        let k = 8;
        let symbol_size = 32;
        let seed = 99u64;

        let source: Vec<Vec<u8>> = (0..k)
            .map(|i| {
                (0..symbol_size)
                    .map(|j| ((i * 53 + j * 19 + 3) % 256) as u8)
                    .collect()
            })
            .collect();

        let encoder = SystematicEncoder::new(&source, symbol_size, seed).unwrap();
        let decoder = InactivationDecoder::new(k, symbol_size, seed);
        let l = decoder.params().l;

        // Start with constraint symbols (LDPC + HDPC with zero data)
        let mut received = decoder.constraint_symbols();

        // Add source symbols
        for (i, data) in source.iter().enumerate() {
            received.push(ReceivedSymbol::source(i as u32, data.clone()));
        }

        // Add repair symbols
        for esi in (k as u32)..(l as u32) {
            let (cols, coefs) = decoder.repair_equation(esi);
            let repair_data = encoder.repair_symbol(esi);
            received.push(ReceivedSymbol::repair(esi, cols, coefs, repair_data));
        }

        let object_id = ObjectId::new_for_test(777);
        let proof = decoder
            .decode_with_proof(&received, object_id, 0)
            .expect("decode should succeed")
            .proof;

        proof
            .replay_and_verify(&received)
            .expect("replay verification should succeed");
    }

    #[test]
    fn replay_verification_detects_mismatch() {
        let k = 6;
        let symbol_size = 24;
        let seed = 17u64;

        let source: Vec<Vec<u8>> = (0..k)
            .map(|i| {
                (0..symbol_size)
                    .map(|j| ((i * 41 + j * 11 + 5) % 256) as u8)
                    .collect()
            })
            .collect();

        let encoder = SystematicEncoder::new(&source, symbol_size, seed).unwrap();
        let decoder = InactivationDecoder::new(k, symbol_size, seed);
        let l = decoder.params().l;

        // Start with constraint symbols (LDPC + HDPC with zero data)
        let mut received = decoder.constraint_symbols();

        // Add source symbols
        for (i, data) in source.iter().enumerate() {
            received.push(ReceivedSymbol::source(i as u32, data.clone()));
        }

        // Add repair symbols
        for esi in (k as u32)..(l as u32) {
            let (cols, coefs) = decoder.repair_equation(esi);
            let repair_data = encoder.repair_symbol(esi);
            received.push(ReceivedSymbol::repair(esi, cols, coefs, repair_data));
        }

        let object_id = ObjectId::new_for_test(42);
        let mut proof = decoder
            .decode_with_proof(&received, object_id, 0)
            .expect("decode should succeed")
            .proof;

        proof.elimination.row_ops = proof.elimination.row_ops.saturating_add(1);

        let err = proof
            .replay_and_verify(&received)
            .expect_err("replay should detect mismatch");
        assert!(err.to_string().contains("row_ops"));
    }
}
