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

use crate::raptorq::decoder::DecodeError;
use crate::types::ObjectId;

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
#[derive(Debug, Clone)]
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
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        self.version.hash(&mut hasher);
        self.config.hash(&mut hasher);
        self.received.hash(&mut hasher);
        self.peeling.hash(&mut hasher);
        self.elimination.hash(&mut hasher);
        self.outcome.hash(&mut hasher);
        hasher.finish()
    }
}

/// Decode configuration captured in the proof.
#[derive(Debug, Clone, Hash)]
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
#[derive(Debug, Clone, Hash)]
pub struct ReceivedSummary {
    /// Total symbols received.
    pub total: usize,
    /// Number of source symbols received.
    pub source_count: usize,
    /// Number of repair symbols received.
    pub repair_count: usize,
    /// ESIs of received symbols (truncated to MAX_RECEIVED_SYMBOLS).
    pub esis: Vec<u32>,
    /// True if ESI list was truncated.
    pub truncated: bool,
}

impl ReceivedSummary {
    /// Create from a list of (ESI, is_source) pairs.
    #[must_use]
    pub fn from_received(symbols: impl Iterator<Item = (u32, bool)>) -> Self {
        let mut source_count = 0;
        let mut repair_count = 0;
        let mut esis = Vec::new();

        for (esi, is_source) in symbols {
            if is_source {
                source_count += 1;
            } else {
                repair_count += 1;
            }
            if esis.len() < MAX_RECEIVED_SYMBOLS {
                esis.push(esi);
            }
        }

        let truncated = source_count + repair_count > MAX_RECEIVED_SYMBOLS;
        Self {
            total: source_count + repair_count,
            source_count,
            repair_count,
            esis,
            truncated,
        }
    }
}

/// Trace of peeling (belief propagation) phase.
#[derive(Debug, Clone, Default, Hash)]
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
#[derive(Debug, Clone, Default, Hash)]
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
#[derive(Debug, Clone, Hash)]
pub struct PivotEvent {
    /// Column being eliminated.
    pub col: usize,
    /// Row selected as pivot.
    pub row: usize,
}

/// Final decode outcome.
#[derive(Debug, Clone, Hash)]
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
#[derive(Debug, Clone, Hash)]
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
}

impl From<&DecodeError> for FailureReason {
    fn from(err: &DecodeError) -> Self {
        match err {
            DecodeError::InsufficientSymbols { received, required } => {
                FailureReason::InsufficientSymbols {
                    received: *received,
                    required: *required,
                }
            }
            DecodeError::SingularMatrix { row } => FailureReason::SingularMatrix {
                row: *row,
                attempted_cols: Vec::new(), // Filled in by caller if available
            },
            DecodeError::SymbolSizeMismatch { expected, actual } => {
                FailureReason::SymbolSizeMismatch {
                    expected: *expected,
                    actual: *actual,
                }
            }
            _ => FailureReason::InsufficientSymbols {
                received: 0,
                required: 0,
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
}
