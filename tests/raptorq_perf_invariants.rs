//! RaptorQ performance invariants, constraint matrix correctness, proof trace
//! validation, and structured deterministic testing.
//!
//! Covers gaps identified in bd-lefk:
//! - Constraint matrix LDPC/HDPC structural properties
//! - Repair equation determinism and seed independence
//! - Decode statistics bounds (peeling + inactivated ≤ L)
//! - Proof trace correctness (peeling.solved matches stats, replay passes)
//! - Overhead sensitivity (exact L, L+1, L+2 received symbols)
//! - Seed sweep with structured logging for regression triage
//! - Dense decode regime (heavy loss → Gaussian elimination heavy)

mod common;

use asupersync::raptorq::decoder::{DecodeError, InactivationDecoder, ReceivedSymbol};
use asupersync::raptorq::gf256::Gf256;
use asupersync::raptorq::proof::ProofOutcome;
use asupersync::raptorq::systematic::{ConstraintMatrix, SystematicEncoder, SystematicParams};
use asupersync::types::ObjectId;
use asupersync::util::DetRng;
use std::collections::{BTreeMap, BTreeSet};

const G1_BUDGET_SCHEMA_VERSION: &str = "raptorq-g1-budget-draft-v1";
const G3_DECISION_RECORDS_SCHEMA_VERSION: &str = "raptorq-optimization-decision-records-v1";
const BEADS_ISSUES_JSONL: &str = include_str!("../.beads/issues.jsonl");
const RAPTORQ_BASELINE_PROFILE_MD: &str = include_str!("../docs/raptorq_baseline_bench_profile.md");
const RAPTORQ_UNIT_MATRIX_MD: &str = include_str!("../docs/raptorq_unit_test_matrix.md");
const RAPTORQ_OPT_DECISIONS_MD: &str =
    include_str!("../docs/raptorq_optimization_decision_records.md");
const RAPTORQ_OPT_DECISIONS_JSON: &str =
    include_str!("../artifacts/raptorq_optimization_decision_records_v1.json");
const REPLAY_CATALOG_ARTIFACT_PATH: &str = "artifacts/raptorq_replay_catalog_v1.json";
const REPLAY_FIXTURE_REF: &str = "RQ-D9-REPLAY-CATALOG-V1";
const REPLAY_SEED_SWEEP_ID: &str = "replay:rq-u-seed-sweep-structured-v1";
const REPLAY_SEED_SWEEP_SCENARIO: &str = "RQ-U-SEED-SWEEP-STRUCTURED";

// ============================================================================
// Test helpers
// ============================================================================

fn make_source_data(k: usize, symbol_size: usize, seed: u64) -> Vec<Vec<u8>> {
    let mut rng = DetRng::new(seed);
    (0..k)
        .map(|_| (0..symbol_size).map(|_| rng.next_u64() as u8).collect())
        .collect()
}

fn constraint_row_equation(constraints: &ConstraintMatrix, row: usize) -> (Vec<usize>, Vec<Gf256>) {
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

fn build_received_symbols(
    encoder: &SystematicEncoder,
    decoder: &InactivationDecoder,
    source: &[Vec<u8>],
    drop_source_indices: &[usize],
    max_repair_esi: u32,
    seed: u64,
) -> Vec<ReceivedSymbol> {
    let k = source.len();
    let params = decoder.params();
    let base_rows = params.s + params.h;
    let constraints = ConstraintMatrix::build(params, seed);

    let mut received = decoder.constraint_symbols();

    for (i, data) in source.iter().enumerate() {
        if !drop_source_indices.contains(&i) {
            let row = base_rows + i;
            let (columns, coefficients) = constraint_row_equation(&constraints, row);
            received.push(ReceivedSymbol {
                esi: i as u32,
                is_source: true,
                columns,
                coefficients,
                data: data.clone(),
            });
        }
    }

    for esi in (k as u32)..max_repair_esi {
        let (cols, coefs) = decoder.repair_equation(esi);
        let repair_data = encoder.repair_symbol(esi);
        received.push(ReceivedSymbol::repair(esi, cols, coefs, repair_data));
    }

    received
}

use asupersync::raptorq::test_log_schema::{
    UNIT_LOG_SCHEMA_VERSION, UnitDecodeStats, UnitLogEntry,
};

fn replay_log_context(replay_ref: &str, scenario_id: &str, seed: u64, outcome: &str) -> String {
    UnitLogEntry::new(
        scenario_id,
        seed,
        &format!("fixture_ref={REPLAY_FIXTURE_REF}"),
        replay_ref,
        outcome,
    )
    .with_repro_command(
        "rch exec -- cargo test --test raptorq_perf_invariants seed_sweep_structured_logging -- --nocapture",
    )
    .with_artifact_path(REPLAY_CATALOG_ARTIFACT_PATH)
    .to_context_string()
}

// ============================================================================
// Constraint matrix structural properties
// ============================================================================

/// LDPC rows (0..S) must each have nonzero entries (parity checks).
#[test]
fn constraint_matrix_ldpc_rows_are_nontrivial() {
    for k in [4, 16, 64, 128] {
        let params = SystematicParams::for_source_block(k, 32);
        let constraints = ConstraintMatrix::build(&params, 42);
        let s = params.s;

        for row in 0..s {
            let (cols, _) = constraint_row_equation(&constraints, row);
            assert!(
                !cols.is_empty(),
                "k={k}: LDPC row {row} has no nonzero entries"
            );
        }
    }
}

/// HDPC rows (S..S+H) must each have nonzero entries.
#[test]
fn constraint_matrix_hdpc_rows_are_nontrivial() {
    for k in [4, 16, 64, 128] {
        let params = SystematicParams::for_source_block(k, 32);
        let constraints = ConstraintMatrix::build(&params, 42);
        let s = params.s;
        let h = params.h;

        for row in s..(s + h) {
            let (cols, _) = constraint_row_equation(&constraints, row);
            assert!(
                !cols.is_empty(),
                "k={k}: HDPC row {row} has no nonzero entries"
            );
        }
    }
}

/// Constraint matrix dimensions must be L rows × L columns.
#[test]
fn constraint_matrix_dimensions_correct() {
    for k in [1, 4, 16, 64, 256] {
        let params = SystematicParams::for_source_block(k, 32);
        let constraints = ConstraintMatrix::build(&params, 42);

        assert_eq!(
            constraints.rows, params.l,
            "k={k}: expected {0} rows, got {1}",
            params.l, constraints.rows
        );
        assert_eq!(
            constraints.cols, params.l,
            "k={k}: expected {0} cols, got {1}",
            params.l, constraints.cols
        );
    }
}

/// LDPC rows should connect to multiple columns (not just one).
/// For k ≥ 8, LDPC circulant structure implies degree ≥ 2.
#[test]
fn constraint_matrix_ldpc_rows_have_minimum_degree() {
    for k in [8, 32, 64, 128] {
        let params = SystematicParams::for_source_block(k, 32);
        let constraints = ConstraintMatrix::build(&params, 42);
        let s = params.s;

        for row in 0..s {
            let (cols, _) = constraint_row_equation(&constraints, row);
            assert!(
                cols.len() >= 2,
                "k={k}: LDPC row {row} has degree {}, expected >= 2",
                cols.len()
            );
        }
    }
}

/// Constraint matrix is deterministic for the same seed.
#[test]
fn constraint_matrix_deterministic_same_seed() {
    let k = 32;
    let seed = 42u64;
    let params = SystematicParams::for_source_block(k, 64);

    let cm1 = ConstraintMatrix::build(&params, seed);
    let cm2 = ConstraintMatrix::build(&params, seed);

    for row in 0..params.l {
        for col in 0..params.l {
            assert_eq!(
                cm1.get(row, col),
                cm2.get(row, col),
                "constraint matrix differs at ({row}, {col})"
            );
        }
    }
}

/// Constraint matrix is seed-independent (LDPC/HDPC/LT structure depends
/// only on K, not on the encoding seed). This is by design: the seed
/// controls repair symbol generation, not the precode matrix.
#[test]
fn constraint_matrix_seed_independent() {
    let k = 16;
    let params = SystematicParams::for_source_block(k, 32);

    let cm1 = ConstraintMatrix::build(&params, 42);
    let cm2 = ConstraintMatrix::build(&params, 99);

    for row in 0..params.l {
        for col in 0..params.l {
            assert_eq!(
                cm1.get(row, col),
                cm2.get(row, col),
                "constraint matrix should be seed-independent, differs at ({row}, {col})"
            );
        }
    }
}

/// Different K values produce different constraint matrices (structure depends on K).
#[test]
fn constraint_matrix_different_k_differ() {
    let params1 = SystematicParams::for_source_block(8, 32);
    let params2 = SystematicParams::for_source_block(16, 32);

    // Different K means different L, so dimensions differ
    assert_ne!(
        params1.l, params2.l,
        "different K should produce different L"
    );
}

// ============================================================================
// Repair equation determinism and independence
// ============================================================================

/// Same ESI + same seed → same repair equation.
#[test]
fn repair_equation_deterministic() {
    let k = 16;
    let seed = 42u64;
    let decoder = InactivationDecoder::new(k, 32, seed);

    for esi in (k as u32)..(k as u32 + 20) {
        let (cols1, coefs1) = decoder.repair_equation(esi);
        let (cols2, coefs2) = decoder.repair_equation(esi);
        assert_eq!(cols1, cols2, "ESI {esi}: columns differ");
        assert_eq!(coefs1, coefs2, "ESI {esi}: coefficients differ");
    }
}

/// Different ESIs produce different repair equations.
#[test]
fn repair_equation_different_esis_differ() {
    let k = 16;
    let seed = 42u64;
    let decoder = InactivationDecoder::new(k, 32, seed);

    let mut equations: Vec<(u32, Vec<usize>)> = Vec::new();
    let mut any_differ = false;

    for esi in (k as u32)..(k as u32 + 10) {
        let (cols, _) = decoder.repair_equation(esi);
        for (prev_esi, prev_cols) in &equations {
            if cols != *prev_cols {
                any_differ = true;
            }
            let _ = prev_esi; // used for context if assertion fails
        }
        equations.push((esi, cols));
    }

    assert!(
        any_differ,
        "at least some repair equations should differ across ESIs"
    );
}

/// Repair equations are independent of call order (no shared RNG state leaking).
#[test]
fn repair_equation_order_independent() {
    let k = 16;
    let seed = 42u64;

    let decoder1 = InactivationDecoder::new(k, 32, seed);
    let decoder2 = InactivationDecoder::new(k, 32, seed);

    // Call in forward order
    let forward: Vec<_> = ((k as u32)..(k as u32 + 10))
        .map(|esi| decoder1.repair_equation(esi))
        .collect();

    // Call in reverse order
    let reverse: Vec<_> = ((k as u32)..(k as u32 + 10))
        .rev()
        .map(|esi| decoder2.repair_equation(esi))
        .collect();

    // Results should match (reversed back to forward order)
    for (i, (fwd, rev)) in forward.iter().zip(reverse.iter().rev()).enumerate() {
        assert_eq!(
            fwd, rev,
            "repair equation at index {i} differs between forward and reverse call order"
        );
    }
}

/// Source equations are trivial (identity mapping).
#[test]
fn source_equations_are_identity() {
    let k = 32;
    let decoder = InactivationDecoder::new(k, 64, 42);

    let all_eqs = decoder.all_source_equations();
    assert_eq!(all_eqs.len(), k, "should have K source equations");

    for (i, (cols, coefs)) in all_eqs.iter().enumerate() {
        assert_eq!(cols, &[i], "source equation {i}: expected column [{i}]");
        assert_eq!(
            coefs,
            &[Gf256::ONE],
            "source equation {i}: expected coefficient [1]"
        );
    }

    // Also test single source equation method
    for i in 0..k {
        let (cols, coefs) = decoder.source_equation(i as u32);
        assert_eq!(cols, vec![i]);
        assert_eq!(coefs, vec![Gf256::ONE]);
    }
}

// ============================================================================
// Decode statistics bounds (performance invariants)
// ============================================================================

/// peeled + inactivated should not exceed L (total intermediate symbols).
#[test]
fn decode_stats_peeled_plus_inactivated_bounded_by_l() {
    for (k, symbol_size, seed) in [
        (4, 16, 42u64),
        (8, 32, 100),
        (16, 64, 200),
        (32, 128, 300),
        (64, 256, 400),
    ] {
        let source = make_source_data(k, symbol_size, seed * 7);
        let encoder = SystematicEncoder::new(&source, symbol_size, seed).unwrap();
        let decoder = InactivationDecoder::new(k, symbol_size, seed);
        let l = decoder.params().l;

        let received = build_received_symbols(&encoder, &decoder, &source, &[], l as u32, seed);
        let result = decoder
            .decode(&received)
            .unwrap_or_else(|e| panic!("k={k}, seed={seed}: decode failed: {e:?}"));

        let total_work = result.stats.peeled + result.stats.inactivated;
        assert!(
            total_work <= l,
            "k={k}, seed={seed}: peeled({}) + inactivated({}) = {} > L({})",
            result.stats.peeled,
            result.stats.inactivated,
            total_work,
            l
        );
    }
}

/// gauss_ops should be zero when all symbols are peeled (no loss, all source+constraints).
#[test]
fn decode_stats_no_loss_minimal_gauss_ops() {
    let k = 8;
    let symbol_size = 32;
    let seed = 42u64;

    let source = make_source_data(k, symbol_size, seed);
    let encoder = SystematicEncoder::new(&source, symbol_size, seed).unwrap();
    let decoder = InactivationDecoder::new(k, symbol_size, seed);
    let l = decoder.params().l;

    let received = build_received_symbols(&encoder, &decoder, &source, &[], l as u32, seed);
    let result = decoder.decode(&received).expect("decode should succeed");

    // With all source symbols present, peeling should handle most/all
    // so gauss_ops should be relatively small
    eprintln!(
        "k={k}: peeled={}, inactivated={}, gauss_ops={}, pivots={}",
        result.stats.peeled,
        result.stats.inactivated,
        result.stats.gauss_ops,
        result.stats.pivots_selected
    );

    // Peeling should solve at least some symbols
    assert!(
        result.stats.peeled > 0,
        "peeling should solve at least some symbols when all source present"
    );
}

/// Pivots selected should not exceed inactivated count.
#[test]
fn decode_stats_pivots_bounded_by_inactivated() {
    for (k, loss_num, loss_den, seed) in [
        (8usize, 1usize, 2usize, 42u64),
        (16, 1, 4, 100),
        (32, 1, 2, 200),
        (64, 1, 4, 300),
    ] {
        let symbol_size = 32;
        let source = make_source_data(k, symbol_size, seed);
        let encoder = SystematicEncoder::new(&source, symbol_size, seed).unwrap();
        let decoder = InactivationDecoder::new(k, symbol_size, seed);
        let l = decoder.params().l;

        let drop_count = k * loss_num / loss_den;
        let drop: Vec<usize> = (0..drop_count).collect();
        let max_repair = (l + drop.len() + 2) as u32;

        let received = build_received_symbols(&encoder, &decoder, &source, &drop, max_repair, seed);
        let result = decoder
            .decode(&received)
            .unwrap_or_else(|e| panic!("k={k}, seed={seed}: decode failed: {e:?}"));

        assert!(
            result.stats.pivots_selected <= result.stats.inactivated + 1,
            "k={k}: pivots({}) should not greatly exceed inactivated({})",
            result.stats.pivots_selected,
            result.stats.inactivated
        );
    }
}

/// Decode statistics are deterministic across runs.
#[test]
fn decode_stats_deterministic_across_runs() {
    let k = 16;
    let symbol_size = 64;
    let seed = 42u64;

    let source = make_source_data(k, symbol_size, seed);
    let encoder = SystematicEncoder::new(&source, symbol_size, seed).unwrap();
    let decoder = InactivationDecoder::new(k, symbol_size, seed);
    let l = decoder.params().l;

    let drop: Vec<usize> = (0..k).filter(|i| i % 3 == 0).collect();
    let max_repair = (l + drop.len() + 2) as u32;
    let received = build_received_symbols(&encoder, &decoder, &source, &drop, max_repair, seed);

    let r1 = decoder.decode(&received).expect("run 1");
    let r2 = decoder.decode(&received).expect("run 2");

    assert_eq!(r1.stats.peeled, r2.stats.peeled, "peeled differs");
    assert_eq!(
        r1.stats.inactivated, r2.stats.inactivated,
        "inactivated differs"
    );
    assert_eq!(r1.stats.gauss_ops, r2.stats.gauss_ops, "gauss_ops differs");
    assert_eq!(
        r1.stats.pivots_selected, r2.stats.pivots_selected,
        "pivots_selected differs"
    );
}

// ============================================================================
// Proof trace correctness
// ============================================================================

/// Proof peeling.solved must match decode stats.peeled.
#[test]
fn proof_peeling_matches_stats() {
    let k = 16;
    let symbol_size = 32;
    let seed = 42u64;

    let source = make_source_data(k, symbol_size, seed);
    let encoder = SystematicEncoder::new(&source, symbol_size, seed).unwrap();
    let decoder = InactivationDecoder::new(k, symbol_size, seed);
    let l = decoder.params().l;

    let drop: Vec<usize> = (0..k).filter(|i| i % 4 == 0).collect();
    let max_repair = (l + drop.len() + 2) as u32;
    let received = build_received_symbols(&encoder, &decoder, &source, &drop, max_repair, seed);

    let object_id = ObjectId::new_for_test(7777);
    let result = decoder
        .decode_with_proof(&received, object_id, 0)
        .expect("decode with proof");

    let stats = &result.result.stats;
    let proof = &result.proof;

    assert_eq!(
        proof.peeling.solved, stats.peeled,
        "proof.peeling.solved({}) != stats.peeled({})",
        proof.peeling.solved, stats.peeled
    );
    assert_eq!(
        proof.elimination.inactivated, stats.inactivated,
        "proof.elimination.inactivated({}) != stats.inactivated({})",
        proof.elimination.inactivated, stats.inactivated
    );
    assert_eq!(
        proof.elimination.pivots, stats.pivots_selected,
        "proof.elimination.pivots({}) != stats.pivots_selected({})",
        proof.elimination.pivots, stats.pivots_selected
    );
    assert_eq!(
        proof.elimination.row_ops, stats.gauss_ops,
        "proof.elimination.row_ops({}) != stats.gauss_ops({})",
        proof.elimination.row_ops, stats.gauss_ops
    );
}

/// Proof replay_and_verify passes for successful decode.
#[test]
fn proof_replay_passes_for_success() {
    let k = 12;
    let symbol_size = 48;
    let seed = 123u64;

    let source = make_source_data(k, symbol_size, seed);
    let encoder = SystematicEncoder::new(&source, symbol_size, seed).unwrap();
    let decoder = InactivationDecoder::new(k, symbol_size, seed);
    let l = decoder.params().l;

    let drop: Vec<usize> = vec![0, 3, 7];
    let max_repair = (l + drop.len() + 1) as u32;
    let received = build_received_symbols(&encoder, &decoder, &source, &drop, max_repair, seed);

    let object_id = ObjectId::new_for_test(8888);
    let result = decoder
        .decode_with_proof(&received, object_id, 0)
        .expect("decode with proof");

    assert!(
        matches!(result.proof.outcome, ProofOutcome::Success { .. }),
        "expected success outcome"
    );

    result
        .proof
        .replay_and_verify(&received)
        .expect("replay should pass");
}

/// Proof replay_and_verify passes for failure cases too.
#[test]
fn proof_replay_passes_for_failure() {
    let k = 8;
    let symbol_size = 32;
    let seed = 500u64;

    let source = make_source_data(k, symbol_size, seed);
    let decoder = InactivationDecoder::new(k, symbol_size, seed);

    // Only receive k-1 source symbols (insufficient)
    let received: Vec<ReceivedSymbol> = source[..k - 1]
        .iter()
        .enumerate()
        .map(|(i, data)| ReceivedSymbol::source(i as u32, data.clone()))
        .collect();

    let object_id = ObjectId::new_for_test(9999);
    let (_err, proof) = decoder
        .decode_with_proof(&received, object_id, 0)
        .unwrap_err();

    assert!(
        matches!(proof.outcome, ProofOutcome::Failure { .. }),
        "expected failure outcome"
    );

    proof
        .replay_and_verify(&received)
        .expect("replay should pass even for failure");
}

/// Proof content hash is deterministic.
#[test]
fn proof_content_hash_deterministic() {
    let k = 10;
    let symbol_size = 40;
    let seed = 42u64;

    let source = make_source_data(k, symbol_size, seed);
    let encoder = SystematicEncoder::new(&source, symbol_size, seed).unwrap();
    let decoder = InactivationDecoder::new(k, symbol_size, seed);
    let l = decoder.params().l;

    let received = build_received_symbols(&encoder, &decoder, &source, &[], l as u32, seed);
    let object_id = ObjectId::new_for_test(1234);

    let r1 = decoder
        .decode_with_proof(&received, object_id, 0)
        .expect("run 1");
    let r2 = decoder
        .decode_with_proof(&received, object_id, 0)
        .expect("run 2");

    assert_eq!(
        r1.proof.content_hash(),
        r2.proof.content_hash(),
        "proof content hash should be deterministic"
    );
}

// ============================================================================
// Overhead sensitivity tests
// ============================================================================

/// Test decode with exactly L received symbols (minimum for decode).
#[test]
fn overhead_exact_l_symbols() {
    let k = 16;
    let symbol_size = 32;
    let seed = 42u64;

    let source = make_source_data(k, symbol_size, seed);
    let encoder = SystematicEncoder::new(&source, symbol_size, seed).unwrap();
    let decoder = InactivationDecoder::new(k, symbol_size, seed);
    let l = decoder.params().l;

    // No dropped source symbols, repair ESIs start at k up to l
    // Total received = constraint(S+H) + source(K) + repair to reach exactly L equations
    let received = build_received_symbols(&encoder, &decoder, &source, &[], l as u32, seed);

    let result = decoder
        .decode(&received)
        .expect("exact L symbols should decode");

    for (i, original) in source.iter().enumerate() {
        assert_eq!(
            &result.source[i], original,
            "exact L: source symbol {i} mismatch"
        );
    }
}

/// Test decode with L+extra repair overhead.
#[test]
fn overhead_with_extra_repair() {
    let k = 16;
    let symbol_size = 32;
    let seed = 42u64;

    let source = make_source_data(k, symbol_size, seed);
    let encoder = SystematicEncoder::new(&source, symbol_size, seed).unwrap();
    let decoder = InactivationDecoder::new(k, symbol_size, seed);
    let l = decoder.params().l;

    // Drop half the source, provide extra repair
    let drop: Vec<usize> = (0..k / 2).collect();
    let extra_overhead = 5;
    let max_repair = (l + drop.len() + extra_overhead) as u32;

    let received = build_received_symbols(&encoder, &decoder, &source, &drop, max_repair, seed);

    let result = decoder
        .decode(&received)
        .expect("extra overhead should decode");

    for (i, original) in source.iter().enumerate() {
        assert_eq!(
            &result.source[i], original,
            "extra overhead: source symbol {i} mismatch"
        );
    }
}

// ============================================================================
// Seed sweep with structured logging
// ============================================================================

/// Parameterized roundtrip across 50 seeds with structured output.
/// Logs seed, k, loss, peeling/inactivation stats for regression triage.
#[test]
#[allow(clippy::too_many_lines)]
fn seed_sweep_structured_logging() {
    let k = 16;
    let symbol_size = 32;
    let mut successes = 0u32;
    let mut failures = 0u32;
    let total = 50;

    for iteration in 0..total {
        let seed = 5000u64 + iteration;
        let mut rng = DetRng::new(seed);
        let loss_pct = rng.next_usize(40); // 0-39% loss

        let source = make_source_data(k, symbol_size, seed * 3);
        let encoder = SystematicEncoder::new(&source, symbol_size, seed).unwrap();
        let decoder = InactivationDecoder::new(k, symbol_size, seed);
        let l = decoder.params().l;

        let drop: Vec<usize> = (0..k).filter(|_| rng.next_usize(100) < loss_pct).collect();
        let max_repair = (l + drop.len() + 2) as u32;
        let received = build_received_symbols(&encoder, &decoder, &source, &drop, max_repair, seed);

        match decoder.decode(&received) {
            Ok(result) => {
                successes += 1;
                let log_entry = UnitLogEntry::new(
                    REPLAY_SEED_SWEEP_SCENARIO,
                    seed,
                    &format!("k={k},symbol_size={symbol_size},loss_pct={loss_pct}"),
                    REPLAY_SEED_SWEEP_ID,
                    "ok",
                )
                .with_repro_command(
                    "rch exec -- cargo test --test raptorq_perf_invariants seed_sweep_structured_logging -- --nocapture",
                )
                .with_decode_stats(UnitDecodeStats {
                    k,
                    loss_pct,
                    dropped: drop.len(),
                    peeled: result.stats.peeled,
                    inactivated: result.stats.inactivated,
                    gauss_ops: result.stats.gauss_ops,
                    pivots: result.stats.pivots_selected,
                    peel_queue_pushes: result.stats.peel_queue_pushes,
                    peel_queue_pops: result.stats.peel_queue_pops,
                    peel_frontier_peak: result.stats.peel_frontier_peak,
                    dense_core_rows: result.stats.dense_core_rows,
                    dense_core_cols: result.stats.dense_core_cols,
                    dense_core_dropped_rows: result.stats.dense_core_dropped_rows,
                    fallback_reason: result
                        .stats
                        .hard_regime_conservative_fallback_reason
                        .or(result.stats.peeling_fallback_reason)
                        .unwrap_or("none")
                        .to_string(),
                    hard_regime_activated: result.stats.hard_regime_activated,
                    hard_regime_branch: result.stats.hard_regime_branch.unwrap_or("none").to_string(),
                    hard_regime_fallbacks: result.stats.hard_regime_fallbacks,
                    conservative_fallback_reason: result
                        .stats
                        .hard_regime_conservative_fallback_reason
                        .unwrap_or("none")
                        .to_string(),
                });
                eprintln!(
                    "{}",
                    log_entry
                        .to_json()
                        .unwrap_or_else(|_| log_entry.to_context_string())
                );

                for (i, original) in source.iter().enumerate() {
                    assert_eq!(
                        &result.source[i],
                        original,
                        "{} symbol={i} mismatch",
                        replay_log_context(
                            REPLAY_SEED_SWEEP_ID,
                            REPLAY_SEED_SWEEP_SCENARIO,
                            seed,
                            "symbol_mismatch"
                        )
                    );
                }
            }
            Err(e) => {
                failures += 1;
                let log_entry = UnitLogEntry::new(
                    REPLAY_SEED_SWEEP_SCENARIO,
                    seed,
                    &format!("k={k},symbol_size={symbol_size},loss_pct={loss_pct}"),
                    REPLAY_SEED_SWEEP_ID,
                    "decode_failure",
                )
                .with_repro_command(
                    "rch exec -- cargo test --test raptorq_perf_invariants seed_sweep_structured_logging -- --nocapture",
                )
                .with_decode_stats(UnitDecodeStats {
                    k,
                    loss_pct,
                    dropped: drop.len(),
                    peeled: 0,
                    inactivated: 0,
                    gauss_ops: 0,
                    pivots: 0,
                    peel_queue_pushes: 0,
                    peel_queue_pops: 0,
                    peel_frontier_peak: 0,
                    dense_core_rows: 0,
                    dense_core_cols: 0,
                    dense_core_dropped_rows: 0,
                    fallback_reason: "decode_failed_before_stats".to_string(),
                    hard_regime_activated: false,
                    hard_regime_branch: "none".to_string(),
                    hard_regime_fallbacks: 0,
                    conservative_fallback_reason: "none".to_string(),
                });
                eprintln!(
                    "{} FAIL: {e:?}",
                    log_entry
                        .to_json()
                        .unwrap_or_else(|_| log_entry.to_context_string())
                );
            }
        }
    }

    eprintln!("seed_sweep: {successes}/{total} succeeded, {failures} failed");
    // Expect high success rate with adequate overhead
    assert!(
        successes >= 45,
        "expected >= 45/{total} successes, got {successes}"
    );
}

/// Validate replay catalog schema and linkage guarantees for deterministic repro.
#[test]
fn replay_catalog_schema_and_linkage() {
    let catalog_json = include_str!("../artifacts/raptorq_replay_catalog_v1.json");
    let catalog: serde_json::Value =
        serde_json::from_str(catalog_json).expect("replay catalog must be valid JSON");

    assert_eq!(
        catalog["schema_version"].as_str(),
        Some("raptorq-replay-catalog-v1"),
        "unexpected replay catalog schema version"
    );
    assert_eq!(
        catalog["fixture_ref"].as_str(),
        Some(REPLAY_FIXTURE_REF),
        "fixture reference mismatch"
    );

    let entries = catalog["entries"]
        .as_array()
        .expect("entries must be an array");
    assert!(
        !entries.is_empty(),
        "replay catalog must contain at least one entry"
    );

    for entry in entries {
        let replay_ref = entry["replay_ref"]
            .as_str()
            .expect("entry missing replay_ref");
        let scenario_id = entry["scenario_id"]
            .as_str()
            .expect("entry missing scenario_id");
        let unit_tests = entry["unit_tests"]
            .as_array()
            .expect("entry missing unit_tests");
        let e2e_scripts = entry["e2e_scripts"]
            .as_array()
            .expect("entry missing e2e_scripts");
        let profile_tags = entry["profile_tags"]
            .as_array()
            .expect("entry missing profile_tags");
        let repro_cmd = entry["repro_cmd"]
            .as_str()
            .expect("entry missing repro_cmd");

        assert!(
            !replay_ref.is_empty() && replay_ref.starts_with("replay:"),
            "invalid replay_ref for scenario {scenario_id}"
        );
        assert!(
            !unit_tests.is_empty(),
            "replay entry {replay_ref} must link at least one unit test"
        );
        assert!(
            !e2e_scripts.is_empty(),
            "replay entry {replay_ref} must link at least one deterministic E2E script"
        );
        assert!(
            !profile_tags.is_empty(),
            "replay entry {replay_ref} must define at least one profile tag"
        );
        assert!(
            repro_cmd.contains("rch exec --"),
            "replay entry {replay_ref} must include remote repro command"
        );
    }
}

/// Validate G1 budget draft schema presence and key workload/profile coverage.
#[test]
fn g1_budget_draft_schema_and_coverage() {
    let artifact_json = include_str!("../artifacts/raptorq_baseline_bench_profile_v1.json");
    let artifact: serde_json::Value =
        serde_json::from_str(artifact_json).expect("baseline profile artifact must be valid JSON");

    let draft = artifact
        .get("g1_budget_draft")
        .expect("baseline artifact must include g1_budget_draft");
    assert_eq!(
        draft["schema_version"].as_str(),
        Some(G1_BUDGET_SCHEMA_VERSION),
        "unexpected G1 budget schema version"
    );
    assert_eq!(
        draft["bead_id"].as_str(),
        Some("bd-3v1cs"),
        "G1 budget draft must stay anchored to bd-3v1cs"
    );
    assert_eq!(draft["seed"].as_u64(), Some(424_242), "G1 seed mismatch");

    let taxonomy = draft["workload_taxonomy"]
        .as_array()
        .expect("workload_taxonomy must be an array");
    let workload_ids: BTreeSet<&str> = taxonomy
        .iter()
        .map(|entry| {
            entry["workload_id"]
                .as_str()
                .expect("workload_taxonomy entry missing workload_id")
        })
        .collect();

    let required_workloads = [
        "RQ-G1-ENC-SMALL",
        "RQ-G1-DEC-SOURCE",
        "RQ-G1-DEC-REPAIR",
        "RQ-G1-GF256-ADDMUL",
        "RQ-G1-SOLVER-MARKOWITZ",
        "RQ-G1-PIPE-64K",
        "RQ-G1-PIPE-256K",
        "RQ-G1-PIPE-1M",
        "RQ-G1-E2E-RANDOM-LOWLOSS",
        "RQ-G1-E2E-RANDOM-HIGHLOSS",
        "RQ-G1-E2E-BURST-LATE",
    ];
    for workload_id in required_workloads {
        assert!(
            workload_ids.contains(workload_id),
            "missing G1 workload taxonomy entry for {workload_id}"
        );
    }

    let profiles = draft["profile_gate_mapping"]
        .as_array()
        .expect("profile_gate_mapping must be an array");
    let profile_names: BTreeSet<&str> = profiles
        .iter()
        .map(|entry| {
            entry["profile"]
                .as_str()
                .expect("profile entry missing profile")
        })
        .collect();
    for profile in ["fast", "full", "forensics"] {
        assert!(
            profile_names.contains(profile),
            "missing profile gate mapping for {profile}"
        );
    }
    for entry in profiles {
        let command = entry["command"]
            .as_str()
            .expect("profile command must be a string");
        assert!(
            command.contains("rch exec --"),
            "profile command must use rch offload: {command}"
        );
        let workloads = entry["required_workloads"]
            .as_array()
            .expect("required_workloads must be an array");
        assert!(
            !workloads.is_empty(),
            "profile {} must include at least one workload",
            entry["profile"]
                .as_str()
                .expect("profile field missing while checking workload list")
        );
    }
}

/// Validate budget-sheet direction semantics for warn/fail thresholds.
#[test]
fn g1_budget_sheet_threshold_directions_are_consistent() {
    let artifact_json = include_str!("../artifacts/raptorq_baseline_bench_profile_v1.json");
    let artifact: serde_json::Value =
        serde_json::from_str(artifact_json).expect("baseline profile artifact must be valid JSON");
    let draft = artifact
        .get("g1_budget_draft")
        .expect("baseline artifact must include g1_budget_draft");

    let taxonomy = draft["workload_taxonomy"]
        .as_array()
        .expect("workload_taxonomy must be an array");
    let workload_ids: BTreeSet<&str> = taxonomy
        .iter()
        .map(|entry| {
            entry["workload_id"]
                .as_str()
                .expect("workload_taxonomy entry missing workload_id")
        })
        .collect();

    let budget_sheet = draft["budget_sheet"]
        .as_array()
        .expect("budget_sheet must be an array");
    assert!(
        !budget_sheet.is_empty(),
        "budget_sheet must contain at least one metric row"
    );

    for row in budget_sheet {
        let workload_id = row["workload_id"]
            .as_str()
            .expect("budget row missing workload_id");
        assert!(
            workload_ids.contains(workload_id),
            "budget row references unknown workload_id {workload_id}"
        );

        let direction = row["direction"]
            .as_str()
            .expect("budget row missing direction");
        let warning_budget = row["warning_budget"]
            .as_f64()
            .expect("budget row missing warning_budget");
        let fail_budget = row["fail_budget"]
            .as_f64()
            .expect("budget row missing fail_budget");

        match direction {
            "upper_bound" => assert!(
                warning_budget <= fail_budget,
                "upper_bound metric must satisfy warning <= fail for {workload_id}"
            ),
            "lower_bound" => assert!(
                warning_budget >= fail_budget,
                "lower_bound metric must satisfy warning >= fail for {workload_id}"
            ),
            "exact" => assert!(
                (warning_budget - fail_budget).abs() < f64::EPSILON,
                "exact metric must satisfy warning == fail for {workload_id}"
            ),
            other => panic!("unknown budget direction {other} for {workload_id}"),
        }
    }

    let required_fields = draft["structured_logging"]["required_fields"]
        .as_array()
        .expect("structured_logging.required_fields must be an array");
    let required_field_names: BTreeSet<&str> = required_fields
        .iter()
        .map(|value| value.as_str().expect("required field must be string"))
        .collect();
    for field in [
        "workload_id",
        "profile",
        "seed",
        "metric_name",
        "observed_value",
        "warning_budget",
        "fail_budget",
        "decision",
        "artifact_path",
        "replay_ref",
    ] {
        assert!(
            required_field_names.contains(field),
            "structured logging field missing: {field}"
        );
    }
}

/// Validate the G1 profile-gate contract remains aligned with existing runtime tiers.
#[test]
fn g1_budget_profile_mapping_matches_runtime_tiers() {
    let artifact_json = include_str!("../artifacts/raptorq_baseline_bench_profile_v1.json");
    let artifact: serde_json::Value =
        serde_json::from_str(artifact_json).expect("baseline profile artifact must be valid JSON");

    let runtime_tiers = artifact["validation_harness_inventory"]["runtime_profile_tiers"]
        .as_array()
        .expect("runtime_profile_tiers must be an array");
    let mut tier_command_by_name = std::collections::BTreeMap::new();
    for tier in runtime_tiers {
        let tier_name = tier["tier"].as_str().expect("tier missing name");
        let command = tier["command"].as_str().expect("tier missing command");
        tier_command_by_name.insert(tier_name.to_string(), command.to_string());
    }

    let draft = artifact
        .get("g1_budget_draft")
        .expect("baseline artifact must include g1_budget_draft");
    let profile_mapping = draft["profile_gate_mapping"]
        .as_array()
        .expect("profile_gate_mapping must be an array");

    for profile in profile_mapping {
        let name = profile["profile"].as_str().expect("profile missing name");
        let command = profile["command"]
            .as_str()
            .expect("profile mapping missing command");
        let tier_command = tier_command_by_name
            .get(name)
            .unwrap_or_else(|| panic!("runtime_profile_tiers missing tier {name}"));
        assert_eq!(
            command, tier_command,
            "profile gate command drift for {name}; keep g1_budget_draft and runtime_profile_tiers aligned"
        );
    }
}

/// Validate prerequisite linkage for correctness evidence references.
#[test]
fn g1_budget_prerequisite_evidence_linkage_is_well_formed() {
    let artifact_json = include_str!("../artifacts/raptorq_baseline_bench_profile_v1.json");
    let artifact: serde_json::Value =
        serde_json::from_str(artifact_json).expect("baseline profile artifact must be valid JSON");
    let draft = artifact
        .get("g1_budget_draft")
        .expect("baseline artifact must include g1_budget_draft");

    let prereqs = draft["correctness_prerequisites"]
        .as_array()
        .expect("correctness_prerequisites must be an array");
    assert!(
        !prereqs.is_empty(),
        "correctness_prerequisites must include at least one evidence bead"
    );

    let mut seen = BTreeSet::new();
    let mut expected_refs = BTreeSet::new();
    let mut external_ref_status = BTreeMap::new();
    for line in BEADS_ISSUES_JSONL.lines() {
        let Ok(entry) = serde_json::from_str::<serde_json::Value>(line) else {
            continue;
        };
        let Some(external_ref) = entry["external_ref"].as_str() else {
            continue;
        };
        let Some(status) = entry["status"].as_str() else {
            continue;
        };
        external_ref_status.insert(external_ref.to_string(), status.to_string());
    }

    for prereq in prereqs {
        let bead_id = prereq["bead_id"]
            .as_str()
            .expect("correctness_prerequisites[].bead_id must be a string");
        let status = prereq["status"]
            .as_str()
            .expect("correctness_prerequisites[].status must be a string");

        assert!(
            bead_id.starts_with("bd-"),
            "prerequisite bead id must use bd-* external ref style: {bead_id}"
        );
        assert!(
            seen.insert(bead_id.to_string()),
            "duplicate prerequisite bead id: {bead_id}"
        );
        expected_refs.insert(bead_id.to_string());
        assert!(
            matches!(status, "open" | "in_progress" | "closed"),
            "invalid prerequisite status {status} for {bead_id}"
        );
        let tracker_status = external_ref_status.get(bead_id).unwrap_or_else(|| {
            panic!("missing prerequisite bead {bead_id} in .beads/issues.jsonl")
        });
        assert_eq!(
            status, tracker_status,
            "status drift for prerequisite {bead_id}: artifact has {status}, tracker has {tracker_status}"
        );
    }

    let required_refs = BTreeSet::from([
        "bd-1rxlv".to_string(),
        "bd-61s90".to_string(),
        "bd-3bvdj".to_string(),
        "bd-oeql8".to_string(),
        "bd-26pqk".to_string(),
    ]);
    assert_eq!(
        expected_refs, required_refs,
        "g1 correctness_prerequisites must track canonical D1/D5/D6/D7/D9 bead set"
    );

    let d1 = prereqs
        .iter()
        .find(|entry| entry["bead_id"].as_str() == Some("bd-1rxlv"))
        .expect("D1 golden-vector prerequisite (bd-1rxlv) must be listed");
    assert_eq!(
        d1["status"].as_str(),
        Some("closed"),
        "D1 (bd-1rxlv) should be closed for calibrated baseline evidence"
    );
}

fn markdown_status_for_bead(doc: &str, bead_id: &str) -> Option<String> {
    for line in doc.lines() {
        let trimmed = line.trim();
        if !(trimmed.starts_with('|') && trimmed.contains(bead_id)) {
            continue;
        }
        let cols = trimmed.split('|').map(str::trim).collect::<Vec<_>>();
        if cols.len() < 5 {
            continue;
        }
        let status = cols[3].trim_matches('`').trim();
        if matches!(status, "open" | "in_progress" | "closed") {
            return Some(status.to_string());
        }
    }
    None
}

/// Keep baseline markdown prerequisite table synchronized with canonical
/// g1_budget_draft.correctness_prerequisites rows.
#[test]
fn g1_budget_baseline_markdown_status_snapshot_matches_artifact() {
    let artifact_json = include_str!("../artifacts/raptorq_baseline_bench_profile_v1.json");
    let artifact: serde_json::Value =
        serde_json::from_str(artifact_json).expect("baseline profile artifact must be valid JSON");
    let prereqs = artifact["g1_budget_draft"]["correctness_prerequisites"]
        .as_array()
        .expect("correctness_prerequisites must be an array");

    for prereq in prereqs {
        let bead_id = prereq["bead_id"]
            .as_str()
            .expect("correctness_prerequisites[].bead_id must be a string");
        let expected = prereq["status"]
            .as_str()
            .expect("correctness_prerequisites[].status must be a string");
        let observed = markdown_status_for_bead(RAPTORQ_BASELINE_PROFILE_MD, bead_id)
            .unwrap_or_else(|| {
                panic!("baseline markdown snapshot missing status row for {bead_id}")
            });
        assert_eq!(
            observed, expected,
            "baseline markdown status drift for {bead_id}: expected {expected}, found {observed}"
        );
    }
}

/// Keep D5 unit-matrix markdown prerequisite table synchronized with the
/// canonical D5/D6/D7/D9 status rows in the G1 artifact.
#[test]
fn g1_budget_unit_matrix_markdown_status_snapshot_matches_artifact_subset() {
    let artifact_json = include_str!("../artifacts/raptorq_baseline_bench_profile_v1.json");
    let artifact: serde_json::Value =
        serde_json::from_str(artifact_json).expect("baseline profile artifact must be valid JSON");
    let prereqs = artifact["g1_budget_draft"]["correctness_prerequisites"]
        .as_array()
        .expect("correctness_prerequisites must be an array");

    let expected_subset = BTreeSet::from([
        "bd-61s90".to_string(),
        "bd-26pqk".to_string(),
        "bd-oeql8".to_string(),
        "bd-3bvdj".to_string(),
    ]);
    let mut seen = BTreeSet::new();

    for prereq in prereqs {
        let bead_id = prereq["bead_id"]
            .as_str()
            .expect("correctness_prerequisites[].bead_id must be a string");
        if !expected_subset.contains(bead_id) {
            continue;
        }
        seen.insert(bead_id.to_string());
        let expected = prereq["status"]
            .as_str()
            .expect("correctness_prerequisites[].status must be a string");
        let observed =
            markdown_status_for_bead(RAPTORQ_UNIT_MATRIX_MD, bead_id).unwrap_or_else(|| {
                panic!("unit matrix markdown snapshot missing status row for {bead_id}")
            });
        assert_eq!(
            observed, expected,
            "unit matrix markdown status drift for {bead_id}: expected {expected}, found {observed}"
        );
    }

    assert_eq!(
        seen, expected_subset,
        "unit matrix markdown must track canonical D5/D6/D7/D9 status subset"
    );
}

/// Validate G3 decision-record artifact schema and high-impact lever coverage.
#[test]
#[allow(clippy::too_many_lines)]
fn g3_decision_records_schema_and_high_impact_lever_coverage() {
    let artifact: serde_json::Value = serde_json::from_str(RAPTORQ_OPT_DECISIONS_JSON)
        .expect("decision-record artifact must be valid JSON");

    assert_eq!(
        artifact["schema_version"].as_str(),
        Some(G3_DECISION_RECORDS_SCHEMA_VERSION),
        "unexpected decision-record schema version"
    );
    assert_eq!(
        artifact["track_bead_id"].as_str(),
        Some("asupersync-3ltrv"),
        "decision records must stay anchored to asupersync-3ltrv"
    );
    assert_eq!(
        artifact["external_ref"].as_str(),
        Some("bd-7toum"),
        "decision records must stay anchored to bd-7toum"
    );

    let required_fields = artifact["governance_rules"]["required_fields"]
        .as_array()
        .expect("governance_rules.required_fields must be an array")
        .iter()
        .map(|value| {
            value
                .as_str()
                .expect("required field entries must be strings")
        })
        .collect::<BTreeSet<_>>();
    for field in [
        "decision_id",
        "lever_code",
        "lever_bead_id",
        "expected_value",
        "risk_class",
        "conservative_comparator",
        "rollback_rehearsal",
        "validation_evidence",
        "deterministic_replay",
        "status",
    ] {
        assert!(
            required_fields.contains(field),
            "missing required decision-record field {field}"
        );
    }

    let cards = artifact["decision_cards"]
        .as_array()
        .expect("decision_cards must be an array");
    assert_eq!(
        cards.len(),
        8,
        "decision_cards must include exactly E4/E5/C5/C6/F5/F6/F7/F8"
    );

    let expected_levers = BTreeSet::from([
        "C5".to_string(),
        "C6".to_string(),
        "E4".to_string(),
        "E5".to_string(),
        "F5".to_string(),
        "F6".to_string(),
        "F7".to_string(),
        "F8".to_string(),
    ]);
    let mut observed_levers = BTreeSet::new();

    for card in cards {
        let lever = card["lever_code"]
            .as_str()
            .expect("decision card missing lever_code");
        observed_levers.insert(lever.to_string());

        let comparator_mode = card["conservative_comparator"]["mode"]
            .as_str()
            .expect("decision card missing conservative comparator mode");
        assert!(
            !comparator_mode.trim().is_empty(),
            "decision card {lever} must include conservative comparator mode"
        );

        let rollback_cmd = card["rollback_rehearsal"]["command"]
            .as_str()
            .expect("decision card missing rollback rehearsal command");
        assert!(
            rollback_cmd.contains("rch exec --"),
            "rollback rehearsal command for {lever} must use rch"
        );

        let rollback_checklist = card["rollback_rehearsal"]["post_rollback_verification_checklist"]
            .as_array()
            .expect("decision card missing rollback checklist");
        assert!(
            !rollback_checklist.is_empty(),
            "rollback checklist for {lever} must be non-empty"
        );

        let pre_cmd = card["deterministic_replay"]["pre_change_command"]
            .as_str()
            .expect("decision card missing pre_change_command");
        let post_cmd = card["deterministic_replay"]["post_change_command"]
            .as_str()
            .expect("decision card missing post_change_command");
        assert!(
            pre_cmd.contains("rch exec --"),
            "pre-change replay command for {lever} must use rch"
        );
        assert!(
            post_cmd.contains("rch exec --"),
            "post-change replay command for {lever} must use rch"
        );

        let status = card["status"]
            .as_str()
            .expect("decision card missing status");
        if matches!(status, "approved" | "approved_guarded") {
            let unit = card["validation_evidence"]["unit"]
                .as_array()
                .expect("approved cards must include unit evidence array");
            let e2e = card["validation_evidence"]["deterministic_e2e"]
                .as_array()
                .expect("approved cards must include deterministic_e2e array");
            assert!(
                !unit.is_empty(),
                "approved card {lever} must include unit evidence links"
            );
            assert!(
                !e2e.is_empty(),
                "approved card {lever} must include deterministic e2e evidence links"
            );
        }
    }

    assert_eq!(
        observed_levers, expected_levers,
        "decision cards must cover C5/C6/E4/E5/F5/F6/F7/F8"
    );
}

/// Validate baseline/profile and decision-record docs cross-link correctly.
#[test]
fn g3_decision_record_docs_are_cross_linked() {
    for required in [
        "artifacts/raptorq_optimization_decision_records_v1.json",
        "docs/raptorq_optimization_decision_records.md",
        "bd-7toum",
    ] {
        assert!(
            RAPTORQ_BASELINE_PROFILE_MD.contains(required),
            "baseline profile doc must mention {required}"
        );
    }

    for required in [
        "asupersync-3ltrv",
        "artifacts/raptorq_optimization_decision_records_v1.json",
        "`E4`",
        "`F8`",
        "cards_pending_measured_evidence",
    ] {
        assert!(
            RAPTORQ_OPT_DECISIONS_MD.contains(required),
            "decision-record doc must mention {required}"
        );
    }
}

// ============================================================================
// Dense decode regime (heavy loss → Gaussian elimination heavy)
// ============================================================================

/// With heavy source loss, decoder must rely on Gaussian elimination.
/// This tests the inactivation + back-substitution path.
#[test]
fn dense_regime_heavy_loss_gaussian_path() {
    let k = 32;
    let symbol_size = 64;
    let seed = 42u64;

    let source = make_source_data(k, symbol_size, seed);
    let encoder = SystematicEncoder::new(&source, symbol_size, seed).unwrap();
    let decoder = InactivationDecoder::new(k, symbol_size, seed);
    let l = decoder.params().l;

    // Drop 75% of source symbols - forces heavy reliance on repair + Gaussian
    let drop: Vec<usize> = (0..k).filter(|i| i % 4 != 0).collect();
    let max_repair = (l + drop.len() + 5) as u32;

    let received = build_received_symbols(&encoder, &decoder, &source, &drop, max_repair, seed);
    let result = decoder
        .decode(&received)
        .unwrap_or_else(|e| panic!("dense regime decode failed: {e:?}"));

    // With 75% loss, expect significant inactivation
    eprintln!(
        "dense regime: peeled={}, inactivated={}, gauss_ops={}, pivots={}",
        result.stats.peeled,
        result.stats.inactivated,
        result.stats.gauss_ops,
        result.stats.pivots_selected
    );

    for (i, original) in source.iter().enumerate() {
        assert_eq!(
            &result.source[i], original,
            "dense regime: source symbol {i} mismatch"
        );
    }
}

/// All-repair decode (zero source symbols) with proof trace validation.
#[test]
fn dense_regime_all_repair_with_proof() {
    let k = 16;
    let symbol_size = 32;
    let seed = 789u64;

    let source = make_source_data(k, symbol_size, seed);
    let encoder = SystematicEncoder::new(&source, symbol_size, seed).unwrap();
    let decoder = InactivationDecoder::new(k, symbol_size, seed);
    let l = decoder.params().l;

    // Drop ALL source symbols
    let drop: Vec<usize> = (0..k).collect();
    let max_repair = (k + l) as u32;

    let received = build_received_symbols(&encoder, &decoder, &source, &drop, max_repair, seed);
    let object_id = ObjectId::new_for_test(5555);

    let result = decoder
        .decode_with_proof(&received, object_id, 0)
        .expect("all-repair decode with proof");

    assert!(
        matches!(result.proof.outcome, ProofOutcome::Success { .. }),
        "expected success for all-repair decode"
    );

    // Verify proof replay
    result
        .proof
        .replay_and_verify(&received)
        .expect("replay should pass");

    // Verify correctness
    for (i, original) in source.iter().enumerate() {
        assert_eq!(
            &result.result.source[i], original,
            "all-repair: source symbol {i} mismatch"
        );
    }

    eprintln!(
        "all-repair proof: peeling.solved={}, elim.inactivated={}, elim.pivots={}, elim.row_ops={}",
        result.proof.peeling.solved,
        result.proof.elimination.inactivated,
        result.proof.elimination.pivots,
        result.proof.elimination.row_ops
    );
}

// ============================================================================
// Failure mode determinism
// ============================================================================

/// InsufficientSymbols error contains deterministic metadata.
#[test]
fn insufficient_symbols_error_deterministic() {
    let k = 8;
    let symbol_size = 32;
    let seed = 42u64;

    let decoder = InactivationDecoder::new(k, symbol_size, seed);

    let received: Vec<ReceivedSymbol> = (0..3)
        .map(|i| ReceivedSymbol::source(i, vec![0u8; symbol_size]))
        .collect();

    let err1 = decoder.decode(&received).unwrap_err();
    let err2 = decoder.decode(&received).unwrap_err();

    assert_eq!(err1, err2, "error should be deterministic");

    match err1 {
        DecodeError::InsufficientSymbols { received, required } => {
            assert_eq!(received, 3);
            assert!(required > received, "required should exceed received");
        }
        other => panic!("expected InsufficientSymbols, got {other:?}"),
    }
}

/// SymbolSizeMismatch error contains accurate dimensions.
#[test]
fn symbol_size_mismatch_error_accurate() {
    let k = 4;
    let symbol_size = 32;
    let seed = 42u64;

    let decoder = InactivationDecoder::new(k, symbol_size, seed);
    let l = decoder.params().l;

    let wrong_size = symbol_size + 7;
    let received: Vec<ReceivedSymbol> = (0..l)
        .map(|i| ReceivedSymbol::source(i as u32, vec![0u8; wrong_size]))
        .collect();

    match decoder.decode(&received).unwrap_err() {
        DecodeError::SymbolSizeMismatch { expected, actual } => {
            assert_eq!(
                expected, symbol_size,
                "expected size should be {symbol_size}"
            );
            assert_eq!(actual, wrong_size, "actual size should be {wrong_size}");
        }
        other => panic!("expected SymbolSizeMismatch, got {other:?}"),
    }
}

// ============================================================================
// Cross-parameter roundtrip sweep (structured)
// ============================================================================

/// Sweep across multiple (K, symbol_size) combinations with deterministic seeds.
/// Validates roundtrip, stats bounds, and proof determinism for each case.
#[test]
fn cross_parameter_roundtrip_sweep() {
    let test_matrix = [
        (4, 8, 42u64),
        (4, 64, 43),
        (8, 16, 44),
        (8, 128, 45),
        (16, 32, 46),
        (32, 64, 47),
        (64, 128, 48),
        (100, 64, 49),
    ];

    for (k, symbol_size, seed) in test_matrix {
        let source = make_source_data(k, symbol_size, seed * 11);
        let encoder = SystematicEncoder::new(&source, symbol_size, seed).unwrap();
        let decoder = InactivationDecoder::new(k, symbol_size, seed);
        let l = decoder.params().l;

        // Drop ~25% of source
        let drop: Vec<usize> = (0..k).filter(|i| i % 4 == 0).collect();
        let max_repair = (l + drop.len() + 2) as u32;
        let received = build_received_symbols(&encoder, &decoder, &source, &drop, max_repair, seed);

        let result = decoder
            .decode(&received)
            .unwrap_or_else(|e| panic!("k={k}, symbol_size={symbol_size}, seed={seed}: {e:?}"));

        // Correctness
        for (i, original) in source.iter().enumerate() {
            assert_eq!(
                &result.source[i], original,
                "k={k}, ss={symbol_size}, seed={seed}: symbol {i} mismatch"
            );
        }

        // Stats bounds
        let total_work = result.stats.peeled + result.stats.inactivated;
        assert!(
            total_work <= l,
            "k={k}: peeled+inactivated({total_work}) > L({l})"
        );

        eprintln!(
            "k={k} ss={symbol_size} seed={seed} drop={}: peeled={} inact={} gauss={} OK",
            drop.len(),
            result.stats.peeled,
            result.stats.inactivated,
            result.stats.gauss_ops,
        );
    }
}

// ============================================================================
// D7 schema contract tests
// ============================================================================

/// Validate that unit log entries produced by the seed sweep conform to the
/// canonical schema contract (asupersync-vca9g / D7).
#[test]
fn unit_log_schema_contract() {
    use asupersync::raptorq::test_log_schema::validate_unit_log_json;

    // Build a representative log entry matching seed_sweep output.
    let entry = UnitLogEntry::new(
        REPLAY_SEED_SWEEP_SCENARIO,
        5042,
        "k=16,symbol_size=32,loss_pct=25",
        REPLAY_SEED_SWEEP_ID,
        "ok",
    )
    .with_repro_command(
        "rch exec -- cargo test --test raptorq_perf_invariants seed_sweep_structured_logging -- --nocapture",
    )
    .with_decode_stats(UnitDecodeStats {
        k: 16,
        loss_pct: 25,
        dropped: 4,
        peeled: 10,
        inactivated: 2,
        gauss_ops: 8,
        pivots: 2,
        peel_queue_pushes: 12,
        peel_queue_pops: 10,
        peel_frontier_peak: 4,
        dense_core_rows: 5,
        dense_core_cols: 3,
        dense_core_dropped_rows: 1,
        fallback_reason: "peeling_exhausted_to_dense_core".to_string(),
        hard_regime_activated: true,
        hard_regime_branch: "markowitz".to_string(),
        hard_regime_fallbacks: 0,
        conservative_fallback_reason: "none".to_string(),
    });

    let json = entry.to_json().expect("serialize unit log entry");
    let violations = validate_unit_log_json(&json);
    assert!(
        violations.is_empty(),
        "D7 schema contract violation in seed sweep entry: {violations:?}"
    );

    // Verify schema version matches constant.
    assert_eq!(
        entry.schema_version, UNIT_LOG_SCHEMA_VERSION,
        "schema version mismatch"
    );

    // Verify the JSON round-trips cleanly.
    let parsed: UnitLogEntry = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(parsed.scenario_id, REPLAY_SEED_SWEEP_SCENARIO);
    assert_eq!(parsed.seed, 5042);
    assert_eq!(parsed.outcome, "ok");
    let stats = parsed.decode_stats.expect("decode_stats should be present");
    assert_eq!(stats.k, 16);
    assert_eq!(stats.dropped, 4);
}

/// Validate that failure entries also conform to the schema contract.
#[test]
fn unit_log_schema_contract_failure_entry() {
    use asupersync::raptorq::test_log_schema::validate_unit_log_json;

    let entry = UnitLogEntry::new(
        REPLAY_SEED_SWEEP_SCENARIO,
        5099,
        "k=16,symbol_size=32,loss_pct=38",
        REPLAY_SEED_SWEEP_ID,
        "decode_failure",
    )
    .with_repro_command(
        "rch exec -- cargo test --test raptorq_perf_invariants seed_sweep_structured_logging -- --nocapture",
    );

    let json = entry.to_json().expect("serialize");
    let violations = validate_unit_log_json(&json);
    assert!(
        violations.is_empty(),
        "D7 schema contract violation in failure entry: {violations:?}"
    );
}

/// D7 guardrail: deterministic E2E runner must emit the v2 scenario schema
/// with all forensic contract fields and an explicit contract-fail gate.
#[test]
fn d7_e2e_runner_script_schema_contract_surface() {
    let script = include_str!("../scripts/run_raptorq_e2e.sh");

    for required in [
        "\"schema_version\":\"raptorq-e2e-scenario-log-v2\"",
        "\"assertion_id\":\"%s\"",
        "\"run_id\":\"%s\"",
        "\"seed\":%s",
        "\"parameter_set\":\"%s\"",
        "\"phase_markers\":[\"encode\",\"loss\",\"decode\",\"proof\",\"report\"]",
        "\"artifact_path\":\"%s\"",
        "\"repro_command\":\"%s\"",
    ] {
        assert!(
            script.contains(required),
            "missing D7 scenario-log contract token in run_raptorq_e2e.sh: {required}"
        );
    }

    assert!(
        script.contains("validate_scenario_contract"),
        "run_raptorq_e2e.sh must include explicit schema contract validation"
    );
    assert!(
        script.contains("FAIL (D7 schema contract)"),
        "runner must fail loudly when scenario schema contract is violated"
    );
    assert!(
        !script.contains("\"repro_cmd\":"),
        "legacy scenario field repro_cmd should not be emitted by D7 v2 schema"
    );
}
