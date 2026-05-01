//! Fuzz target for RaptorQ decode-proof replay fail-closed behavior.
//!
//! Treats arbitrary input bytes as a bounded `DecodeProof`, replays it against
//! an empty received-symbol set, and asserts corrupted proofs are rejected.

#![no_main]

use std::panic::{AssertUnwindSafe, catch_unwind};

use arbitrary::{Arbitrary, Unstructured};
use asupersync::raptorq::decoder::InactivationDecoder;
use asupersync::raptorq::proof::{
    DecodeConfig, DecodeProof, EliminationTrace, FailureReason, InactivationStrategy,
    MAX_PIVOT_EVENTS, MAX_RECEIVED_SYMBOLS, PeelingTrace, PivotEvent, ProofOutcome,
    ReceivedSummary, StrategyTransition,
};
use asupersync::types::ObjectId;
use libfuzzer_sys::fuzz_target;

const MAX_K: usize = 32;
const MAX_SYMBOL_SIZE: usize = 64;
const MAX_LIST_ITEMS: usize = 16;

#[derive(Debug, Arbitrary)]
struct CorruptProofInput {
    version: u8,
    object_id: u128,
    sbn: u8,
    k: u8,
    symbol_size: u8,
    seed: u64,
    config_s_delta: u8,
    config_h_delta: u8,
    config_l_delta: u8,
    received: RawReceivedSummary,
    peeling: RawPeelingTrace,
    elimination: RawEliminationTrace,
    outcome: RawProofOutcome,
}

#[derive(Debug, Arbitrary)]
struct RawReceivedSummary {
    total: u16,
    source_count: u16,
    repair_count: u16,
    esi_multiset_hash: u64,
    esis: Vec<u32>,
    truncated: bool,
}

#[derive(Debug, Arbitrary)]
struct RawPeelingTrace {
    solved: u16,
    solved_indices: Vec<u16>,
    truncated: bool,
}

#[derive(Debug, Arbitrary)]
struct RawEliminationTrace {
    strategy: u8,
    inactivated: u16,
    inactive_cols: Vec<u16>,
    pivots: u16,
    pivot_events: Vec<RawPivotEvent>,
    inactive_cols_truncated: bool,
    pivot_events_truncated: bool,
    row_ops: u16,
    strategy_transitions: Vec<RawStrategyTransition>,
    strategy_transitions_truncated: bool,
}

#[derive(Debug, Arbitrary)]
struct RawPivotEvent {
    col: u16,
    row: u16,
}

#[derive(Debug, Arbitrary)]
struct RawStrategyTransition {
    from: u8,
    to: u8,
    reason: u8,
}

#[derive(Debug, Arbitrary)]
enum RawProofOutcome {
    Success {
        symbols_recovered: u16,
        source_payload_hash: u64,
    },
    Failure {
        reason: RawFailureReason,
    },
}

#[derive(Debug, Arbitrary)]
enum RawFailureReason {
    InsufficientSymbols {
        received: u16,
        required: u16,
    },
    SingularMatrix {
        row: u16,
        attempted_cols: Vec<u16>,
    },
    SymbolSizeMismatch {
        expected: u16,
        actual: u16,
    },
    SymbolEquationArityMismatch {
        esi: u32,
        columns: u16,
        coefficients: u16,
    },
    ColumnIndexOutOfRange {
        esi: u32,
        column: u16,
        max_valid: u16,
    },
    SourceEsiOutOfRange {
        esi: u32,
        max_valid: u16,
    },
    InvalidSourceSymbolEquation {
        esi: u32,
        expected_column: u16,
    },
    CorruptDecodedOutput {
        esi: u32,
        byte_index: u16,
        expected: u8,
        actual: u8,
    },
}

fuzz_target!(|data: &[u8]| {
    let mut unstructured = Unstructured::new(data);
    let Ok(input) = CorruptProofInput::arbitrary(&mut unstructured) else {
        return;
    };

    let mut proof = input.into_decode_proof();
    let expected = expected_empty_replay_proof(&proof.config);
    if proof == expected {
        proof.version = proof.version.wrapping_add(1);
    }
    assert_ne!(
        proof, expected,
        "corrupt proof generator must not feed an unmodified canonical proof"
    );

    let verification = catch_unwind(AssertUnwindSafe(|| proof.replay_and_verify(&[])));
    match verification {
        Ok(Ok(())) => panic!("corrupt DecodeProof false-accepted"),
        Ok(Err(_)) => {}
        Err(_) => panic!("corrupt DecodeProof replay panicked"),
    }
});

impl CorruptProofInput {
    fn into_decode_proof(self) -> DecodeProof {
        let k = bounded_nonzero(self.k, MAX_K);
        let symbol_size = bounded_nonzero(self.symbol_size, MAX_SYMBOL_SIZE);
        let decoder = InactivationDecoder::new(k, symbol_size, self.seed);
        let params = decoder.params();

        DecodeProof {
            version: self.version,
            config: DecodeConfig {
                object_id: ObjectId::from_u128(self.object_id),
                sbn: self.sbn,
                k,
                s: params.s + usize::from(self.config_s_delta % 3),
                h: params.h + usize::from(self.config_h_delta % 3),
                l: params.l + usize::from(self.config_l_delta % 3),
                symbol_size,
                seed: self.seed,
            },
            received: self.received.into_summary(),
            peeling: self.peeling.into_trace(),
            elimination: self.elimination.into_trace(),
            outcome: self.outcome.into_outcome(),
        }
    }
}

impl RawReceivedSummary {
    fn into_summary(mut self) -> ReceivedSummary {
        self.esis.truncate(MAX_LIST_ITEMS.min(MAX_RECEIVED_SYMBOLS));
        self.esis.sort_unstable();
        ReceivedSummary {
            total: bounded_usize(self.total, MAX_LIST_ITEMS),
            source_count: bounded_usize(self.source_count, MAX_LIST_ITEMS),
            repair_count: bounded_usize(self.repair_count, MAX_LIST_ITEMS),
            esi_multiset_hash: self.esi_multiset_hash,
            esis: self.esis,
            truncated: self.truncated,
        }
    }
}

impl RawPeelingTrace {
    fn into_trace(mut self) -> PeelingTrace {
        self.solved_indices
            .truncate(MAX_LIST_ITEMS.min(MAX_PIVOT_EVENTS));
        PeelingTrace {
            solved: bounded_usize(self.solved, MAX_LIST_ITEMS),
            solved_indices: self.solved_indices.into_iter().map(usize::from).collect(),
            truncated: self.truncated,
        }
    }
}

impl RawEliminationTrace {
    fn into_trace(mut self) -> EliminationTrace {
        self.inactive_cols
            .truncate(MAX_LIST_ITEMS.min(MAX_PIVOT_EVENTS));
        self.pivot_events
            .truncate(MAX_LIST_ITEMS.min(MAX_PIVOT_EVENTS));
        self.strategy_transitions
            .truncate(MAX_LIST_ITEMS.min(MAX_PIVOT_EVENTS));

        EliminationTrace {
            strategy: strategy_from_byte(self.strategy),
            inactivated: bounded_usize(self.inactivated, MAX_LIST_ITEMS),
            inactive_cols: self.inactive_cols.into_iter().map(usize::from).collect(),
            pivots: bounded_usize(self.pivots, MAX_LIST_ITEMS),
            pivot_events: self
                .pivot_events
                .into_iter()
                .map(|event| PivotEvent {
                    col: usize::from(event.col),
                    row: usize::from(event.row),
                })
                .collect(),
            inactive_cols_truncated: self.inactive_cols_truncated,
            pivot_events_truncated: self.pivot_events_truncated,
            row_ops: bounded_usize(self.row_ops, MAX_LIST_ITEMS),
            strategy_transitions: self
                .strategy_transitions
                .into_iter()
                .map(|transition| StrategyTransition {
                    from: strategy_from_byte(transition.from),
                    to: strategy_from_byte(transition.to),
                    reason: reason_from_byte(transition.reason),
                })
                .collect(),
            strategy_transitions_truncated: self.strategy_transitions_truncated,
        }
    }
}

impl RawProofOutcome {
    fn into_outcome(self) -> ProofOutcome {
        match self {
            Self::Success {
                symbols_recovered,
                source_payload_hash,
            } => ProofOutcome::Success {
                symbols_recovered: bounded_usize(symbols_recovered, MAX_LIST_ITEMS),
                source_payload_hash,
            },
            Self::Failure { reason } => ProofOutcome::Failure {
                reason: reason.into_reason(),
            },
        }
    }
}

impl RawFailureReason {
    fn into_reason(self) -> FailureReason {
        match self {
            Self::InsufficientSymbols { received, required } => {
                FailureReason::InsufficientSymbols {
                    received: bounded_usize(received, MAX_LIST_ITEMS),
                    required: bounded_usize(required, MAX_LIST_ITEMS),
                }
            }
            Self::SingularMatrix {
                row,
                mut attempted_cols,
            } => {
                attempted_cols.truncate(MAX_LIST_ITEMS);
                FailureReason::SingularMatrix {
                    row: bounded_usize(row, MAX_LIST_ITEMS),
                    attempted_cols: attempted_cols.into_iter().map(usize::from).collect(),
                }
            }
            Self::SymbolSizeMismatch { expected, actual } => FailureReason::SymbolSizeMismatch {
                expected: bounded_usize(expected, MAX_SYMBOL_SIZE),
                actual: bounded_usize(actual, MAX_SYMBOL_SIZE),
            },
            Self::SymbolEquationArityMismatch {
                esi,
                columns,
                coefficients,
            } => FailureReason::SymbolEquationArityMismatch {
                esi,
                columns: bounded_usize(columns, MAX_LIST_ITEMS),
                coefficients: bounded_usize(coefficients, MAX_LIST_ITEMS),
            },
            Self::ColumnIndexOutOfRange {
                esi,
                column,
                max_valid,
            } => FailureReason::ColumnIndexOutOfRange {
                esi,
                column: bounded_usize(column, MAX_LIST_ITEMS),
                max_valid: bounded_usize(max_valid, MAX_LIST_ITEMS),
            },
            Self::SourceEsiOutOfRange { esi, max_valid } => FailureReason::SourceEsiOutOfRange {
                esi,
                max_valid: bounded_usize(max_valid, MAX_LIST_ITEMS),
            },
            Self::InvalidSourceSymbolEquation {
                esi,
                expected_column,
            } => FailureReason::InvalidSourceSymbolEquation {
                esi,
                expected_column: bounded_usize(expected_column, MAX_LIST_ITEMS),
            },
            Self::CorruptDecodedOutput {
                esi,
                byte_index,
                expected,
                actual,
            } => FailureReason::CorruptDecodedOutput {
                esi,
                byte_index: bounded_usize(byte_index, MAX_SYMBOL_SIZE),
                expected,
                actual,
            },
        }
    }
}

fn expected_empty_replay_proof(config: &DecodeConfig) -> DecodeProof {
    let decoder = InactivationDecoder::new(config.k, config.symbol_size, config.seed);
    match decoder.decode_with_proof(&[], config.object_id, config.sbn) {
        Ok(result) => result.proof,
        Err((_err, proof)) => proof,
    }
}

fn bounded_nonzero(value: u8, max: usize) -> usize {
    (usize::from(value) % max).saturating_add(1)
}

fn bounded_usize(value: u16, max: usize) -> usize {
    usize::from(value) % (max + 1)
}

fn strategy_from_byte(value: u8) -> InactivationStrategy {
    match value % 3 {
        0 => InactivationStrategy::AllAtOnce,
        1 => InactivationStrategy::HighSupportFirst,
        _ => InactivationStrategy::BlockSchurLowRank,
    }
}

fn reason_from_byte(value: u8) -> &'static str {
    const REASONS: &[&str] = &[
        "fuzz/no-transition",
        "fuzz/high-support",
        "fuzz/block-schur",
        "fuzz/fallback",
    ];
    REASONS[usize::from(value) % REASONS.len()]
}
