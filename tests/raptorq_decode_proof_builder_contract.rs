//! RaptorQ `DecodeProofBuilder` assembly + terminal-outcome contract.
//!
//! bd-3uox5 (RAPTORQ-RFC6330) AC5 (structured forensic logging schema) + AC6
//! (every failure path has a stable, reproducible artifact). The decode-proof
//! builder (`src/raptorq/proof.rs`) is how the decoder assembles the forensic
//! artifact operators replay, but its assembly surface had ZERO integration
//! coverage:
//!   - `DecodeProof::builder` / `DecodeProofBuilder::set_received`
//!   - `DecodeProofBuilder::{peeling_mut, elimination_mut}`
//!   - `DecodeProofBuilder::{set_success, set_failure, build}`
//!
//! The sibling recorder crates exercise the trace value types in isolation;
//! this crate pins how the BUILDER threads them into a finished `DecodeProof`
//! and enforces the safety guards on its terminal transitions.
//!
//! Guarantees pinned:
//!   1. `build()` threads config / received / peeling / elimination / outcome
//!      through unchanged and stamps the current `PROOF_SCHEMA_VERSION`.
//!   2. `peeling_mut` / `elimination_mut` hand back LIVE handles to the
//!      builder's own traces (mutations survive into the built proof) and the
//!      two traces are independent.
//!   3. `set_success` records the recovered-symbol count and a deterministic,
//!      content-sensitive payload hash; `set_failure` records the exact reason.
//!   4. The br-asupersync-gvxrxv exactly-once guard: a second terminal call
//!      (success-after-failure, or success-twice) panics rather than silently
//!      overwriting an attested outcome.
//!   5. `build()` fails closed (panics) when `received` or the outcome was
//!      never set.
//!
//! Repro: `cargo test --test raptorq_decode_proof_builder_contract`

use asupersync::raptorq::proof::{
    DecodeConfig, DecodeProof, FailureReason, InactivationStrategy, PROOF_SCHEMA_VERSION,
    ProofOutcome, ReceivedSummary,
};
use asupersync::types::ObjectId;

/// A fresh, fixed decode configuration (built per call so tests never share a
/// moved/cloned instance).
fn cfg() -> DecodeConfig {
    DecodeConfig {
        object_id: ObjectId::new(7, 99),
        sbn: 1,
        k: 10,
        s: 3,
        h: 2,
        l: 15,
        symbol_size: 64,
        seed: 42,
    }
}

fn summary_of(symbols: &[(u32, bool)]) -> ReceivedSummary {
    ReceivedSummary::from_received(symbols.iter().copied())
}

#[test]
fn build_threads_all_components_unchanged() {
    let received = summary_of(&[(0, true), (1, true), (12, false)]);
    let mut builder = DecodeProof::builder(cfg());
    builder.set_received(received.clone());
    builder.peeling_mut().record_solved(3);
    builder.elimination_mut().record_pivot(5, 6);
    builder.set_failure(FailureReason::InsufficientSymbols {
        received: 3,
        required: 10,
    });
    let proof = builder.build();

    assert_eq!(
        proof.version, PROOF_SCHEMA_VERSION,
        "build must stamp the current schema version"
    );
    assert_eq!(proof.config, cfg(), "config must thread through unchanged");
    assert_eq!(
        proof.received, received,
        "received summary must thread through"
    );
    assert_eq!(
        proof.peeling.solved, 1,
        "peeling mutation must survive build"
    );
    assert_eq!(
        proof.peeling.solved_indices,
        vec![3],
        "peeling event must survive build"
    );
    assert_eq!(
        proof.elimination.pivots, 1,
        "elimination mutation must survive"
    );
    assert_eq!(
        proof.outcome,
        ProofOutcome::Failure {
            reason: FailureReason::InsufficientSymbols {
                received: 3,
                required: 10,
            }
        },
        "outcome must thread through unchanged"
    );
}

#[test]
fn peeling_mut_and_elimination_mut_are_live_independent_handles() {
    let mut builder = DecodeProof::builder(cfg());
    builder.set_received(summary_of(&[(0, true)]));

    // Drive each trace exclusively through its accessor.
    let peeling = builder.peeling_mut();
    peeling.record_solved(11);
    peeling.record_solved(22);

    let elimination = builder.elimination_mut();
    elimination.set_strategy(InactivationStrategy::HighSupportFirst);
    elimination.record_inactivation(4);
    elimination.record_row_op();
    elimination.record_row_op();

    builder.set_success(&vec![vec![0u8; 64]; 10]);
    let proof = builder.build();

    // Peeling reflects only the peeling ops; elimination only the elimination
    // ops — the two handles point at independent internal traces.
    assert_eq!(proof.peeling.solved, 2);
    assert_eq!(proof.peeling.solved_indices, vec![11, 22]);
    assert_eq!(
        proof.elimination.strategy,
        InactivationStrategy::HighSupportFirst
    );
    assert_eq!(proof.elimination.inactivated, 1);
    assert_eq!(proof.elimination.row_ops, 2);
    assert_eq!(
        proof.elimination.inactive_cols,
        vec![4],
        "inactivation column recorded via the live handle"
    );
    // Cross-field independence: peeling ops left elimination counters at zero
    // for everything but what we drove.
    assert_eq!(proof.elimination.pivots, 0);
    assert!(!proof.peeling.truncated);
}

#[test]
fn set_success_records_count_and_deterministic_content_hash() {
    let recovered_a: Vec<Vec<u8>> = (0..10).map(|i| vec![i as u8; 64]).collect();
    let recovered_a2 = recovered_a.clone();
    // Same length, different content.
    let recovered_b: Vec<Vec<u8>> = (0..10).map(|i| vec![(i + 1) as u8; 64]).collect();

    let hash_of = |recovered: &[Vec<u8>]| -> u64 {
        let mut builder = DecodeProof::builder(cfg());
        builder.set_received(summary_of(&[(0, true)]));
        builder.set_success(recovered);
        match builder.build().outcome {
            ProofOutcome::Success {
                symbols_recovered,
                source_payload_hash,
            } => {
                assert_eq!(
                    symbols_recovered,
                    recovered.len(),
                    "symbols_recovered must equal the recovered slice length"
                );
                source_payload_hash
            }
            ProofOutcome::Failure { reason } => {
                panic!("expected Success outcome, got Failure({reason:?})")
            }
        }
    };

    let ha = hash_of(&recovered_a);
    let ha2 = hash_of(&recovered_a2);
    let hb = hash_of(&recovered_b);
    assert_eq!(
        ha, ha2,
        "identical payloads must hash identically (deterministic)"
    );
    assert_ne!(
        ha, hb,
        "distinct recovered payloads must change the source payload hash"
    );
}

#[test]
fn set_failure_records_exact_reason() {
    let mut builder = DecodeProof::builder(cfg());
    builder.set_received(summary_of(&[]));
    let reason = FailureReason::SingularMatrix {
        row: 7,
        attempted_cols: vec![0, 1, 2],
    };
    builder.set_failure(reason.clone());
    assert_eq!(builder.build().outcome, ProofOutcome::Failure { reason });
}

#[test]
#[should_panic(expected = "outcome already set")]
fn set_success_after_failure_panics() {
    // br-asupersync-gvxrxv: a builder must take exactly one terminal transition.
    let mut builder = DecodeProof::builder(cfg());
    builder.set_received(summary_of(&[]));
    builder.set_failure(FailureReason::InsufficientSymbols {
        received: 0,
        required: 1,
    });
    builder.set_success(&vec![vec![0u8; 64]; 10]); // must panic
}

#[test]
#[should_panic(expected = "outcome already set")]
fn set_success_twice_panics() {
    let mut builder = DecodeProof::builder(cfg());
    builder.set_received(summary_of(&[]));
    builder.set_success(&vec![vec![0u8; 64]; 10]);
    builder.set_success(&vec![vec![1u8; 64]; 10]); // must panic
}

#[test]
#[should_panic(expected = "received must be set")]
fn build_without_received_panics() {
    let mut builder = DecodeProof::builder(cfg());
    builder.set_failure(FailureReason::InsufficientSymbols {
        received: 0,
        required: 1,
    });
    let _ = builder.build(); // must panic: received never set
}

#[test]
#[should_panic(expected = "outcome must be set")]
fn build_without_outcome_panics() {
    let mut builder = DecodeProof::builder(cfg());
    builder.set_received(summary_of(&[(0, true)]));
    let _ = builder.build(); // must panic: outcome never set
}
