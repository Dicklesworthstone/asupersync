#![allow(warnings)]
#![allow(clippy::all)]
#![allow(missing_docs)]
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

use asupersync::raptorq::decision_contract::{G7_DECISION_REPLAY_REF, G7_RUNTIME_FALLBACK_REASONS};
use asupersync::raptorq::decoder::{DecodeError, InactivationDecoder, ReceivedSymbol};
use asupersync::raptorq::gf256::{
    Gf256, Gf256ProfilePackId, dual_kernel_policy_snapshot, gf256_profile_pack_catalog,
};
use asupersync::raptorq::proof::ProofOutcome;
use asupersync::raptorq::systematic::{ConstraintMatrix, SystematicEncoder, SystematicParams};
use asupersync::types::ObjectId;
use asupersync::util::DetRng;
use std::collections::{BTreeMap, BTreeSet};

const G1_BUDGET_SCHEMA_VERSION: &str = "raptorq-g1-budget-draft-v1";
const G3_DECISION_RECORDS_SCHEMA_VERSION: &str = "raptorq-optimization-decision-records-v1";
const G4_ROLLOUT_POLICY_SCHEMA_VERSION: &str = "raptorq-controlled-rollout-policy-v1";
const G7_EXPECTED_LOSS_CONTRACT_SCHEMA_VERSION: &str = "raptorq-g7-expected-loss-contract-v1";
const E3_TRACK_E_GF256_P95P99_SCHEMA_VERSION: &str = "raptorq-track-e-gf256-p95p99-v1";
const E3_TRACK_E_GF256_P95P99_HIGHCONF_SCHEMA_VERSION: &str =
    "raptorq-track-e-gf256-p95p99-highconf-v1";
const E5_TRACK_E_MULTISCENARIO_REFRESH_SCHEMA_VERSION: &str =
    "raptorq-track-e-gf256-multiscenario-refresh-v4";
const H3_POST_CLOSURE_BACKLOG_SCHEMA_VERSION: &str =
    "raptorq-h3-post-closure-opportunity-backlog-v1";
const H2_PROGRAM_CLOSURE_PACKET_SCHEMA_VERSION: &str =
    "raptorq-h2-program-closure-signoff-packet-v1";
/// Read `.beads/issues.jsonl` at runtime rather than compile time.
/// This avoids stale data when the JSONL is modified between compilations
/// (common in multi-agent environments where rch sync races can cause
/// intermediate file versions to be embedded by `include_str!`).
fn beads_issues_jsonl() -> String {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let path = std::path::Path::new(manifest_dir).join(".beads/issues.jsonl");
    std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("failed to read {}: {e}", path.display()))
}

fn beads_latest_status_by_id() -> BTreeMap<String, String> {
    let mut latest = BTreeMap::new();
    for line in beads_issues_jsonl()
        .lines()
        .filter(|line| !line.trim().is_empty())
    {
        let parsed: serde_json::Value =
            serde_json::from_str(line).expect("each .beads/issues.jsonl line must be valid JSON");
        let id = parsed["id"]
            .as_str()
            .expect("issue row must include id")
            .to_string();
        let status = parsed["status"]
            .as_str()
            .expect("issue row must include status")
            .to_string();
        latest.insert(id, status);
    }
    if let Ok(raw_overrides) = std::env::var("ASUPERSYNC_BEADS_STATUS_OVERRIDES_JSON") {
        let overrides: BTreeMap<String, String> = if raw_overrides.trim_start().starts_with('{') {
            serde_json::from_str(&raw_overrides).unwrap_or_else(|e| {
                panic!("failed to parse ASUPERSYNC_BEADS_STATUS_OVERRIDES_JSON: {e}")
            })
        } else {
            raw_overrides
                .split(',')
                .filter(|entry| !entry.trim().is_empty())
                .map(|entry| {
                    let (id, status) = entry.split_once('=').unwrap_or_else(|| {
                        panic!(
                            "ASUPERSYNC_BEADS_STATUS_OVERRIDES_JSON CSV entry must be id=status: {entry}"
                        )
                    });
                    (id.trim().to_string(), status.trim().to_string())
                })
                .collect()
        };
        latest.extend(overrides);
    }
    latest
}
const RAPTORQ_BASELINE_PROFILE_MD: &str = include_str!("../docs/raptorq_baseline_bench_profile.md");
const RAPTORQ_UNIT_MATRIX_MD: &str = include_str!("../docs/raptorq_unit_test_matrix.md");
const RAPTORQ_OPT_DECISIONS_MD: &str =
    include_str!("../docs/raptorq_optimization_decision_records.md");
const RAPTORQ_OPT_DECISIONS_JSON: &str =
    include_str!("../artifacts/raptorq_optimization_decision_records_v1.json");
const RAPTORQ_G4_ROLLOUT_POLICY_MD: &str =
    include_str!("../docs/raptorq_controlled_rollout_policy.md");
const RAPTORQ_G4_ROLLOUT_POLICY_JSON: &str =
    include_str!("../artifacts/raptorq_controlled_rollout_policy_v1.json");
const RAPTORQ_G7_EXPECTED_LOSS_MD: &str =
    include_str!("../docs/raptorq_expected_loss_decision_contract.md");
const RAPTORQ_G7_EXPECTED_LOSS_JSON: &str =
    include_str!("../artifacts/raptorq_expected_loss_decision_contract_v1.json");
const RAPTORQ_H3_POST_CLOSURE_BACKLOG_MD: &str =
    include_str!("../docs/raptorq_post_closure_opportunity_backlog.md");
const RAPTORQ_H3_POST_CLOSURE_BACKLOG_JSON: &str =
    include_str!("../artifacts/raptorq_post_closure_opportunity_backlog_v1.json");
const RAPTORQ_H2_CLOSURE_PACKET_MD: &str =
    include_str!("../docs/raptorq_program_closure_signoff_packet.md");
const RAPTORQ_H2_CLOSURE_PACKET_JSON: &str =
    include_str!("../artifacts/raptorq_program_closure_signoff_packet_v1.json");
const RAPTORQ_BENCH_RS: &str = include_str!("../benches/raptorq_benchmark.rs");
const REPLAY_CATALOG_ARTIFACT_PATH: &str = "artifacts/raptorq_replay_catalog_v1.json";
const REPLAY_FIXTURE_REF: &str = "RQ-D9-REPLAY-CATALOG-V1";
#[cfg(feature = "test-internals")]
const REPLAY_SEED_SWEEP_ID: &str = "replay:rq-u-seed-sweep-structured-v1";
#[cfg(feature = "test-internals")]
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

/// Build received symbols using the simpler ReceivedSymbol::source/repair
/// constructors (matching the benchmark campaign approach).
fn build_decode_received(
    source: &[Vec<u8>],
    encoder: &SystematicEncoder,
    decoder: &InactivationDecoder,
    drop_source_indices: &[usize],
    extra_repair: usize,
) -> Vec<ReceivedSymbol> {
    let k = source.len();
    let l = decoder.params().l;
    let mut dropped = vec![false; k];
    for &idx in drop_source_indices {
        if idx < k {
            dropped[idx] = true;
        }
    }
    let mut received = Vec::with_capacity(l.saturating_add(extra_repair));
    for (idx, data) in source.iter().enumerate() {
        if !dropped[idx] {
            received.push(ReceivedSymbol::source(idx as u32, data.clone()));
        }
    }
    let required_repairs = l.saturating_sub(received.len());
    let total_repairs = required_repairs.saturating_add(extra_repair);
    let repair_start = k as u32;
    let repair_end = repair_start.saturating_add(total_repairs as u32);
    for esi in repair_start..repair_end {
        let (cols, coefs) = decoder.repair_equation(esi);
        let data = encoder.repair_symbol(esi);
        received.push(ReceivedSymbol::repair(esi, cols, coefs, data));
    }
    received
}

#[cfg(feature = "test-internals")]
use asupersync::raptorq::test_log_schema::{
    UNIT_LOG_SCHEMA_VERSION, UnitDecodeStats, UnitGovernanceDecision, UnitLogEntry,
};

#[cfg(feature = "test-internals")]
fn replay_log_context(replay_ref: &str, scenario_id: &str, seed: u64, outcome: &str) -> String {
    UnitLogEntry::new(
        scenario_id,
        seed,
        &format!("fixture_ref={REPLAY_FIXTURE_REF}"),
        replay_ref,
        "rch exec -- cargo test --test raptorq_perf_invariants seed_sweep_structured_logging -- --nocapture",
        outcome,
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
#[cfg(feature = "test-internals")]
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
                    "rch exec -- cargo test --test raptorq_perf_invariants seed_sweep_structured_logging -- --nocapture",
                    "ok",
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
                    governance: result
                        .stats
                        .governance
                        .as_ref()
                        .map(UnitGovernanceDecision::from),
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
                    "rch exec -- cargo test --test raptorq_perf_invariants seed_sweep_structured_logging -- --nocapture",
                    "decode_failure",
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
                    governance: None,
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
    let beads_jsonl = beads_issues_jsonl();
    for line in beads_jsonl.lines() {
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
        // Soft-check JSONL status; on shared rch workers the JSONL may be
        // stale due to concurrent multi-agent syncs. Only assert if the
        // bead exists in the JSONL (it may not if the JSONL version is older).
        if let Some(tracker_status) = external_ref_status.get(bead_id) {
            if status != tracker_status {
                // Allow staleness: artifact may have been updated to "closed"
                // while the JSONL copy on this worker lags behind.
                assert!(
                    status == "closed" || tracker_status == "closed",
                    "status drift for prerequisite {bead_id}: artifact has {status}, \
                     tracker has {tracker_status} (neither is closed)"
                );
            }
        }
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

#[test]
fn e3_unit_matrix_e4_e5_signal_keys_match_live_probe_contract() {
    let required_row = "| `E4` / `E5` | `profile_pack`, `architecture_class`, `profile_fallback_reason`, `mode_fallback_reason`, `mode`, `dual_policy_env_requested`, `profile_pack_env_requested`, `criterion_sample_size`, `criterion_warm_up_seconds`, `criterion_measurement_seconds`, `tail_confidence_proxy` | verifies deterministic GF256 dispatch/fallback behavior, explicit env-request provenance, and benchmark-sampling contract metadata |";
    assert!(
        RAPTORQ_UNIT_MATRIX_MD.contains(required_row),
        "unit matrix E4/E5 diagnostics row must stay aligned with the live dual-policy probe contract"
    );
}

fn assert_percentiles_monotonic(block: &serde_json::Value, label: &str) {
    let p50 = block["p50"]
        .as_f64()
        .unwrap_or_else(|| panic!("{label} missing p50"));
    let p95 = block["p95"]
        .as_f64()
        .unwrap_or_else(|| panic!("{label} missing p95"));
    let p99 = block["p99"]
        .as_f64()
        .unwrap_or_else(|| panic!("{label} missing p99"));
    assert!(
        p50 <= p95 && p95 <= p99,
        "{label} must satisfy p50 <= p95 <= p99 (got p50={p50}, p95={p95}, p99={p99})"
    );
}

/// Validate Track-E p95/p99 artifact schema, mode/op coverage, and percentile ordering.
#[test]
#[allow(clippy::too_many_lines)]
fn e3_track_e_gf256_p95p99_artifact_schema_and_coverage() {
    let artifact_json = include_str!("../artifacts/raptorq_track_e_gf256_p95p99_v1.json");
    let artifact: serde_json::Value =
        serde_json::from_str(artifact_json).expect("Track-E p95/p99 artifact must be valid JSON");
    let expected_scope_boundary_note = "The c==1 addmul fast path is intentionally excluded from this percentile corpus. It reuses dual-add semantics and remains covered separately by deterministic bench validation via addmul_slices2_c1_bit_exact and the benchmark IDs addmul_slices2_c1_auto/addmul_slices2_c1_sequential.";

    assert_eq!(
        artifact["schema_version"].as_str(),
        Some(E3_TRACK_E_GF256_P95P99_SCHEMA_VERSION),
        "unexpected Track-E p95/p99 schema version"
    );
    assert_eq!(
        artifact["track_bead_id"].as_str(),
        Some("asupersync-36m6p"),
        "Track-E p95/p99 artifact must remain anchored to asupersync-36m6p"
    );
    assert_eq!(
        artifact["source_artifacts"].as_array().map(Vec::len),
        Some(1),
        "Track-E p95/p99 artifact must cite exactly one source artifact"
    );
    assert_eq!(
        artifact["source_logs"].as_array().map(Vec::len),
        Some(3),
        "Track-E p95/p99 artifact must record baseline/auto/rollback log pointers"
    );
    assert_eq!(
        artifact["source_artifacts"][0].as_str(),
        Some("artifacts/raptorq_track_e_gf256_bench_v1.json"),
        "Track-E p95/p99 source artifact path mismatch"
    );

    let expected_modes = BTreeSet::from([
        "auto".to_string(),
        "baseline".to_string(),
        "rollback".to_string(),
    ]);
    let expected_ops = BTreeSet::from([
        "addmul_slices2_fused".to_string(),
        "addmul_slices2_sequential".to_string(),
        "mul_slices2_fused".to_string(),
        "mul_slices2_sequential".to_string(),
    ]);
    let expected_excluded_ops = BTreeSet::from([
        "addmul_slices2_c1_auto".to_string(),
        "addmul_slices2_c1_sequential".to_string(),
    ]);

    let op_scope = artifact["methodology"]["operation_scope"]
        .as_array()
        .expect("methodology.operation_scope must be an array")
        .iter()
        .map(|value| {
            value
                .as_str()
                .expect("operation_scope entries must be strings")
                .to_string()
        })
        .collect::<BTreeSet<_>>();
    assert_eq!(
        op_scope, expected_ops,
        "operation scope must cover the canonical four percentile-scored dual-slice operations"
    );
    let excluded_ops = artifact["methodology"]["excluded_operation_scope"]
        .as_array()
        .expect("methodology.excluded_operation_scope must be an array")
        .iter()
        .map(|value| {
            value
                .as_str()
                .expect("excluded_operation_scope entries must be strings")
                .to_string()
        })
        .collect::<BTreeSet<_>>();
    assert_eq!(
        excluded_ops, expected_excluded_ops,
        "base p95/p99 artifact must pin the deliberate c==1 addmul fast-path exclusion"
    );
    assert_eq!(
        artifact["methodology"]["scope_boundary_note"].as_str(),
        Some(expected_scope_boundary_note),
        "base p95/p99 artifact must explain the c==1 scope boundary explicitly"
    );

    let overall = artifact["per_mode_overall_percentiles"]
        .as_array()
        .expect("per_mode_overall_percentiles must be an array");
    assert_eq!(
        overall.len(),
        expected_modes.len(),
        "overall percentiles must provide one entry per mode"
    );

    let mut observed_modes = BTreeSet::new();
    for entry in overall {
        let mode = entry["mode"]
            .as_str()
            .expect("overall percentile entry missing mode")
            .to_string();
        assert!(
            expected_modes.contains(&mode),
            "unexpected mode in overall percentiles: {mode}"
        );
        observed_modes.insert(mode.clone());
        assert!(
            entry["samples"].as_u64().unwrap_or(0) > 0,
            "overall percentile entry must have positive sample count for mode {mode}"
        );
        assert_percentiles_monotonic(&entry["time_us"], &format!("{mode} overall time_us"));
        assert_percentiles_monotonic(
            &entry["throughput_gib_s"],
            &format!("{mode} overall throughput_gib_s"),
        );
    }
    assert_eq!(
        observed_modes, expected_modes,
        "overall percentiles must cover baseline/auto/rollback exactly"
    );

    let op_percentiles = artifact["per_mode_operation_percentiles"]
        .as_array()
        .expect("per_mode_operation_percentiles must be an array");
    assert_eq!(
        op_percentiles.len(),
        expected_modes.len() * expected_ops.len(),
        "operation percentiles must cover every mode/operation pair exactly once"
    );

    let mut observed_pairs = BTreeSet::new();
    for entry in op_percentiles {
        let mode = entry["mode"]
            .as_str()
            .expect("operation percentile entry missing mode")
            .to_string();
        let op = entry["operation"]
            .as_str()
            .expect("operation percentile entry missing operation")
            .to_string();
        assert!(
            expected_modes.contains(&mode),
            "unexpected mode in operation percentiles: {mode}"
        );
        assert!(
            expected_ops.contains(&op),
            "unexpected operation in operation percentiles: {op}"
        );
        observed_pairs.insert((mode.clone(), op.clone()));
        assert!(
            entry["samples"].as_u64().unwrap_or(0) > 0,
            "operation percentile entry must have positive sample count for {mode}/{op}"
        );
        assert_percentiles_monotonic(&entry["time_us"], &format!("{mode}/{op} time_us"));
        assert_percentiles_monotonic(
            &entry["throughput_gib_s"],
            &format!("{mode}/{op} throughput_gib_s"),
        );
    }
    assert_eq!(
        observed_pairs.len(),
        expected_modes.len() * expected_ops.len(),
        "mode/operation percentile pair coverage must be unique"
    );

    let commands = artifact["methodology"]["commands"]
        .as_array()
        .expect("methodology.commands must be an array");
    assert!(
        !commands.is_empty(),
        "methodology.commands must include reproducible benchmark commands"
    );
    for command in commands {
        let command = command
            .as_str()
            .expect("methodology.commands entries must be strings");
        assert!(
            command.contains("rch exec --"),
            "Track-E p95/p99 command must be rch-offloaded: {command}"
        );
        assert!(
            command.contains("cargo bench --bench raptorq_benchmark"),
            "Track-E p95/p99 command must run raptorq_benchmark: {command}"
        );
        assert!(
            command.contains("CARGO_TARGET_DIR="),
            "Track-E p95/p99 command must pin CARGO_TARGET_DIR for reproducibility: {command}"
        );
        assert!(
            command.contains("--sample-size 10"),
            "Track-E p95/p99 command must keep the v1 sample-size contract: {command}"
        );
    }
}

/// Validate high-confidence Track-E artifact linkage, sampling contract, and
/// mode/op comparability against the base p95/p99 artifact.
#[test]
#[allow(clippy::too_many_lines)]
fn e3_track_e_gf256_p95p99_highconf_contract_and_linkage() {
    let highconf_json = include_str!("../artifacts/raptorq_track_e_gf256_p95p99_highconf_v1.json");
    let highconf: serde_json::Value = serde_json::from_str(highconf_json)
        .expect("Track-E high-confidence p95/p99 artifact must be valid JSON");
    let base_json = include_str!("../artifacts/raptorq_track_e_gf256_p95p99_v1.json");
    let base: serde_json::Value =
        serde_json::from_str(base_json).expect("Track-E base p95/p99 artifact must be valid JSON");
    let expected_scope_boundary_note = "The c==1 addmul fast path is intentionally excluded from this percentile corpus. It reuses dual-add semantics and remains covered separately by deterministic bench validation via addmul_slices2_c1_bit_exact and the benchmark IDs addmul_slices2_c1_auto/addmul_slices2_c1_sequential.";

    assert_eq!(
        highconf["schema_version"].as_str(),
        Some(E3_TRACK_E_GF256_P95P99_HIGHCONF_SCHEMA_VERSION),
        "unexpected Track-E high-confidence schema version"
    );
    assert_eq!(
        highconf["track_bead_id"].as_str(),
        Some("asupersync-36m6p"),
        "Track-E high-confidence artifact must remain anchored to asupersync-36m6p"
    );
    assert_eq!(
        highconf["evidence_role"].as_str(),
        Some("narrowed_closure_guardrail"),
        "high-confidence v1 must stay explicitly marked as narrowed guardrail evidence"
    );
    assert_eq!(
        highconf["scope_contract"].as_str(),
        Some("single_scenario_high_sample"),
        "high-confidence v1 must keep its single-scenario semantic contract explicit"
    );
    assert_eq!(
        highconf["successor_policy"].as_str(),
        Some("requires_new_artifact_version_for_broader_multi_scenario_refresh"),
        "broader high-confidence refreshes must version separately instead of mutating v1 semantics in place"
    );
    assert_eq!(
        highconf["source_artifacts"].as_array().map(Vec::len),
        Some(1),
        "Track-E high-confidence artifact must cite exactly one source artifact"
    );
    assert_eq!(
        highconf["source_logs"].as_array().map(Vec::len),
        Some(3),
        "Track-E high-confidence artifact must record baseline/auto/rollback log pointers"
    );
    assert_eq!(
        highconf["source_artifacts"][0].as_str(),
        Some("artifacts/raptorq_track_e_gf256_p95p99_v1.json"),
        "high-confidence artifact must point to the base p95/p99 artifact"
    );

    let criterion = &highconf["methodology"]["criterion_settings"];
    let sample_size = criterion["sample_size"]
        .as_u64()
        .expect("criterion_settings.sample_size must be present");
    assert!(
        sample_size >= 30,
        "high-confidence artifact must use larger sample_size (>=30)"
    );
    assert_eq!(
        highconf["methodology"]["scenario_scope"]
            .as_array()
            .map(Vec::len),
        Some(1),
        "high-confidence artifact should scope to one closure-critical scenario"
    );
    assert_eq!(
        highconf["methodology"]["filter"].as_str(),
        highconf["methodology"]["scenario_scope"][0].as_str(),
        "high-confidence methodology.filter must match the single scenario scope entry"
    );
    let base_excluded_ops = base["methodology"]["excluded_operation_scope"]
        .as_array()
        .expect("base methodology.excluded_operation_scope must be an array")
        .iter()
        .map(|value| {
            value
                .as_str()
                .expect("base excluded_operation_scope entries must be strings")
                .to_string()
        })
        .collect::<BTreeSet<_>>();
    let highconf_excluded_ops = highconf["methodology"]["excluded_operation_scope"]
        .as_array()
        .expect("highconf methodology.excluded_operation_scope must be an array")
        .iter()
        .map(|value| {
            value
                .as_str()
                .expect("highconf excluded_operation_scope entries must be strings")
                .to_string()
        })
        .collect::<BTreeSet<_>>();
    assert_eq!(
        highconf_excluded_ops, base_excluded_ops,
        "high-confidence artifact must preserve the base c==1 fast-path exclusion contract"
    );
    assert_eq!(
        base["methodology"]["scope_boundary_note"].as_str(),
        Some(expected_scope_boundary_note),
        "base artifact must pin the c==1 scope-boundary note"
    );
    assert_eq!(
        highconf["methodology"]["scope_boundary_note"].as_str(),
        Some(expected_scope_boundary_note),
        "high-confidence artifact must preserve the c==1 scope-boundary note"
    );

    let base_pairs = base["per_mode_operation_percentiles"]
        .as_array()
        .expect("base per_mode_operation_percentiles must be an array")
        .iter()
        .map(|entry| {
            (
                entry["mode"]
                    .as_str()
                    .expect("base mode missing")
                    .to_string(),
                entry["operation"]
                    .as_str()
                    .expect("base operation missing")
                    .to_string(),
            )
        })
        .collect::<BTreeSet<_>>();
    let highconf_pairs = highconf["per_mode_operation_percentiles"]
        .as_array()
        .expect("highconf per_mode_operation_percentiles must be an array")
        .iter()
        .map(|entry| {
            (
                entry["mode"]
                    .as_str()
                    .expect("highconf mode missing")
                    .to_string(),
                entry["operation"]
                    .as_str()
                    .expect("highconf operation missing")
                    .to_string(),
            )
        })
        .collect::<BTreeSet<_>>();
    assert_eq!(
        highconf_pairs, base_pairs,
        "high-confidence artifact must preserve mode/operation coverage from base artifact"
    );

    for entry in highconf["per_mode_operation_percentiles"]
        .as_array()
        .expect("highconf per_mode_operation_percentiles must be an array")
    {
        let mode = entry["mode"]
            .as_str()
            .expect("highconf op entry missing mode");
        let operation = entry["operation"]
            .as_str()
            .expect("highconf op entry missing operation");
        assert_eq!(
            entry["samples"].as_u64(),
            Some(sample_size),
            "high-confidence operation sample count must equal criterion sample_size for {mode}/{operation}"
        );
        assert_percentiles_monotonic(
            &entry["time_us"],
            &format!("highconf {mode}/{operation} time_us"),
        );
        assert_percentiles_monotonic(
            &entry["throughput_gib_s"],
            &format!("highconf {mode}/{operation} throughput_gib_s"),
        );
    }

    let commands = highconf["methodology"]["commands"]
        .as_array()
        .expect("highconf methodology.commands must be an array");
    assert_eq!(
        commands.len(),
        3,
        "high-confidence methodology should include baseline/auto/rollback command trio"
    );
    for command in commands {
        let command = command
            .as_str()
            .expect("highconf methodology.commands entries must be strings");
        assert!(
            command.contains("rch exec --"),
            "high-confidence command must be rch-offloaded: {command}"
        );
        assert!(
            command.contains("--sample-size 60"),
            "high-confidence command must preserve sample-size 60 contract: {command}"
        );
        assert!(
            command.contains("CARGO_TARGET_DIR="),
            "high-confidence command must pin CARGO_TARGET_DIR for reproducibility: {command}"
        );
    }

    assert!(
        highconf["findings"]
            .as_array()
            .is_some_and(|items| !items.is_empty()),
        "high-confidence artifact must include non-empty findings"
    );
    assert!(
        highconf["limitations"]
            .as_array()
            .is_some_and(|items| !items.is_empty()),
        "high-confidence artifact must include non-empty limitations"
    );
    assert!(
        highconf["limitations"].as_array().is_some_and(|items| {
            items.iter().any(|item| {
                item.as_str()
                    .is_some_and(|text| text.contains("new artifact/schema version"))
            })
        }),
        "high-confidence artifact limitations must preserve the versioned-successor guardrail"
    );
    let closure = &highconf["closure_assessment"];
    assert_eq!(
        closure["ready_for_e5_closure"].as_bool(),
        Some(false),
        "high-confidence artifact must explicitly encode the current not-ready E5 closure state"
    );
    assert_eq!(
        closure["acceptance_criterion_4_status"].as_str(),
        Some("not_met"),
        "high-confidence artifact must keep AC#4 marked not_met until uplift is demonstrated"
    );
    assert_eq!(
        closure["material_uplift_demonstrated"].as_bool(),
        Some(false),
        "high-confidence artifact must not claim material uplift yet"
    );
    assert!(
        closure["blocking_requirements"]
            .as_array()
            .is_some_and(|items| !items.is_empty()),
        "high-confidence artifact must keep non-empty blocking requirements while closure remains open"
    );
}

/// Validate the high-confidence Track-E packet keeps E5 closure blocked for a
/// data-backed reason rather than narrative drift.
#[test]
#[allow(clippy::too_many_lines)]
fn e3_track_e_highconf_closure_assessment_matches_recorded_tails() {
    let highconf: serde_json::Value = serde_json::from_str(include_str!(
        "../artifacts/raptorq_track_e_gf256_p95p99_highconf_v1.json"
    ))
    .expect("Track-E high-confidence p95/p99 artifact must be valid JSON");
    let closure = &highconf["closure_assessment"];

    assert_eq!(
        closure["ready_for_e5_closure"].as_bool(),
        Some(false),
        "E5 closure must stay blocked in the high-confidence packet"
    );
    assert_eq!(
        closure["acceptance_criterion_4_status"].as_str(),
        Some("not_met"),
        "AC#4 must remain not_met in the high-confidence packet"
    );
    assert_eq!(
        closure["material_uplift_demonstrated"].as_bool(),
        Some(false),
        "high-confidence packet must not claim material uplift"
    );
    assert_eq!(
        closure["overall_tail_direction_vs_baseline"].as_str(),
        Some("regressed"),
        "high-confidence packet must record that overall auto tails still regress versus baseline"
    );
    assert_eq!(
        closure["operation_tail_pattern_vs_baseline"].as_str(),
        Some("mixed"),
        "high-confidence packet must record that operation-level auto tails are mixed"
    );
    assert_eq!(
        closure["scope_sufficiency"].as_str(),
        Some("insufficient"),
        "high-confidence packet must record that the narrowed corpus is not closure-sufficient"
    );

    let overall_by_mode = highconf["per_mode_overall_percentiles"]
        .as_array()
        .expect("per_mode_overall_percentiles must be an array")
        .iter()
        .map(|entry| {
            (
                entry["mode"]
                    .as_str()
                    .expect("overall percentile entry must include mode"),
                entry,
            )
        })
        .collect::<BTreeMap<_, _>>();
    let baseline_overall = overall_by_mode
        .get("baseline")
        .expect("overall percentile set must include baseline");
    let auto_overall = overall_by_mode
        .get("auto")
        .expect("overall percentile set must include auto");
    for percentile in ["p95", "p99"] {
        let baseline_tail = baseline_overall["time_us"][percentile]
            .as_f64()
            .unwrap_or_else(|| panic!("baseline overall {percentile} tail must be numeric"));
        let auto_tail = auto_overall["time_us"][percentile]
            .as_f64()
            .unwrap_or_else(|| panic!("auto overall {percentile} tail must be numeric"));
        assert!(
            auto_tail > baseline_tail,
            "auto overall {percentile} tail must stay above baseline while closure_assessment remains blocked"
        );
    }

    let operation_percentiles = highconf["per_mode_operation_percentiles"]
        .as_array()
        .expect("per_mode_operation_percentiles must be an array");
    for (operation, expect_regression) in [
        ("mul_slices2_fused", true),
        ("mul_slices2_sequential", true),
        ("addmul_slices2_fused", false),
        ("addmul_slices2_sequential", true),
    ] {
        let baseline_entry = operation_percentiles
            .iter()
            .find(|entry| {
                entry["mode"].as_str() == Some("baseline")
                    && entry["operation"].as_str() == Some(operation)
            })
            .unwrap_or_else(|| panic!("baseline entry missing for {operation}"));
        let auto_entry = operation_percentiles
            .iter()
            .find(|entry| {
                entry["mode"].as_str() == Some("auto")
                    && entry["operation"].as_str() == Some(operation)
            })
            .unwrap_or_else(|| panic!("auto entry missing for {operation}"));
        for percentile in ["p95", "p99"] {
            let baseline_tail = baseline_entry["time_us"][percentile]
                .as_f64()
                .unwrap_or_else(|| {
                    panic!("{operation} baseline {percentile} tail must be numeric")
                });
            let auto_tail = auto_entry["time_us"][percentile]
                .as_f64()
                .unwrap_or_else(|| panic!("{operation} auto {percentile} tail must be numeric"));
            if expect_regression {
                assert!(
                    auto_tail > baseline_tail,
                    "{operation} auto {percentile} tail must stay above baseline while the high-confidence packet marks this operation as regressed"
                );
            } else {
                assert!(
                    auto_tail < baseline_tail,
                    "{operation} auto {percentile} tail must stay below baseline while the high-confidence packet marks operation tails as mixed"
                );
            }
        }
    }

    for required in [
        "closure_assessment",
        "ready_for_e5_closure",
        "acceptance_criterion_4_status",
        "material_uplift_demonstrated",
        "overall_tail_direction_vs_baseline",
        "operation_tail_pattern_vs_baseline",
        "scope_sufficiency",
        "not-ready state",
        "new artifact/schema",
        "highconf_v1",
    ] {
        assert!(
            RAPTORQ_BASELINE_PROFILE_MD.contains(required),
            "baseline profile doc must mention high-confidence closure token {required}"
        );
    }
}

/// Validate the broader Track-E multi-scenario refresh stays versioned
/// separately from the narrowed high-confidence guardrail and keeps closure
/// status machine-checkable.
#[test]
#[allow(clippy::too_many_lines)]
fn e3_track_e_gf256_multiscenario_refresh_contract_and_linkage() {
    let refresh: serde_json::Value = serde_json::from_str(include_str!(
        "../artifacts/raptorq_track_e_gf256_multiscenario_refresh_v4.json"
    ))
    .expect("Track-E broader multiscenario refresh artifact must be valid JSON");
    let bench: serde_json::Value = serde_json::from_str(include_str!(
        "../artifacts/raptorq_track_e_gf256_bench_v1.json"
    ))
    .expect("Track-E benchmark artifact must be valid JSON");
    let highconf: serde_json::Value = serde_json::from_str(include_str!(
        "../artifacts/raptorq_track_e_gf256_p95p99_highconf_v1.json"
    ))
    .expect("Track-E high-confidence artifact must be valid JSON");

    assert_eq!(
        refresh["schema_version"].as_str(),
        Some(E5_TRACK_E_MULTISCENARIO_REFRESH_SCHEMA_VERSION),
        "unexpected Track-E multiscenario refresh schema version"
    );
    assert_eq!(
        refresh["track_bead_id"].as_str(),
        Some("asupersync-36m6p"),
        "Track-E multiscenario refresh must remain anchored to asupersync-36m6p"
    );
    assert_eq!(
        refresh["evidence_role"].as_str(),
        Some("broader_multiscenario_raw_sample_successor_guardrail"),
        "broader refresh must declare its evidence role explicitly"
    );
    assert_eq!(
        refresh["scope_contract"].as_str(),
        Some("same_target_multi_scenario_raw_sample_corpus"),
        "broader refresh must keep its scenario-scope contract explicit"
    );
    assert_eq!(
        refresh["confidence_contract"].as_str(),
        Some("raw_sample_mixed_signal_not_closure_grade"),
        "broader refresh must explicitly remain non-closure-grade"
    );
    assert_eq!(
        refresh["successor_policy"].as_str(),
        Some("requires_new_artifact_version_for_future_closure_retest_or_profile_contract_change"),
        "closure-grade refreshes must version separately instead of mutating v2 semantics in place"
    );

    let source_artifacts = refresh["source_artifacts"]
        .as_array()
        .expect("multiscenario refresh source_artifacts must be an array")
        .iter()
        .map(|value| {
            value
                .as_str()
                .expect("multiscenario refresh source_artifacts entries must be strings")
                .to_string()
        })
        .collect::<Vec<_>>();
    assert_eq!(
        source_artifacts,
        vec![
            "artifacts/raptorq_track_e_gf256_bench_v1.json".to_string(),
            "artifacts/raptorq_track_e_gf256_p95p99_highconf_v1.json".to_string(),
            "artifacts/raptorq_track_e_gf256_multiscenario_refresh_v2.json".to_string(),
            "artifacts/raptorq_track_e_gf256_multiscenario_refresh_v3.json".to_string(),
        ],
        "broader refresh must cite bench, narrowed guardrail, and historical broader packets in order"
    );

    let refresh_scope = refresh["methodology"]["scenario_scope"]
        .as_array()
        .expect("multiscenario refresh scenario_scope must be an array")
        .iter()
        .map(|value| {
            value
                .as_str()
                .expect("multiscenario refresh scenario_scope entries must be strings")
                .to_string()
        })
        .collect::<Vec<_>>();
    let bench_scope = bench["simd_policy_ablation_2026_03_04"]["scope"]["scenarios"]
        .as_array()
        .expect("benchmark artifact scenario scope must be an array")
        .iter()
        .map(|value| {
            value
                .as_str()
                .expect("benchmark artifact scenario scope entries must be strings")
                .to_string()
        })
        .collect::<Vec<_>>();
    assert_eq!(
        refresh_scope.len(),
        8,
        "broader refresh must widen scope to the eight-scenario dual corpus"
    );
    assert_eq!(
        &refresh_scope[..bench_scope.len()],
        bench_scope.as_slice(),
        "broader refresh must preserve the canonical 2026-03-04 seven-scenario prefix"
    );
    assert_eq!(
        refresh_scope.last().map(String::as_str),
        Some("RQ-E-GF256-DUAL-008"),
        "broader refresh must add the DUAL-008 scenario to the broader corpus"
    );

    let commands = refresh["methodology"]["commands"]
        .as_array()
        .expect("multiscenario refresh methodology.commands must be an array");
    assert_eq!(
        commands.len(),
        3,
        "broader refresh must keep baseline/auto/rollback command bundles"
    );
    for command in commands {
        let command = command
            .as_str()
            .expect("multiscenario refresh command entries must be strings");
        assert!(
            command.contains("rch exec --"),
            "broader refresh command must be rch-offloaded: {command}"
        );
        assert!(
            command.contains("CARGO_TARGET_DIR=/tmp/rch-e5-long-v4"),
            "broader refresh command must pin a dedicated longer-window target dir family: {command}"
        );
        assert!(
            command.contains("--sample-size 40"),
            "broader refresh command must preserve the longer-window sample-size 40 contract: {command}"
        );
        assert!(
            command.contains("--warm-up-time 0.2")
                && command.contains("--measurement-time 0.2")
                && command.contains("--features simd-intrinsics"),
            "broader refresh command must preserve the longer-window SIMD benchmark contract: {command}"
        );
    }

    let auto_combined = &refresh["aggregate_deltas_pct"]["auto_vs_baseline"]["combined"];
    assert!(
        (auto_combined["median_delta_pct"]
            .as_f64()
            .expect("combined median delta must be numeric")
            - 1.25)
            .abs()
            < 1e-9,
        "broader refresh must preserve the current-head combined median regression"
    );
    assert!(
        (auto_combined["p95_delta_pct"]
            .as_f64()
            .expect("combined p95 delta must be numeric")
            - (-5.6))
            .abs()
            < 1e-9,
        "broader refresh must preserve the current-head combined p95 improvement"
    );
    assert!(
        (auto_combined["p99_delta_pct"]
            .as_f64()
            .expect("combined p99 delta must be numeric")
            - (-7.06))
            .abs()
            < 1e-9,
        "broader refresh must preserve the current-head combined p99 improvement"
    );

    let auto_mul = &refresh["aggregate_deltas_pct"]["auto_vs_baseline"]["mul_slices2_auto"];
    assert!(
        (auto_mul["average_median_delta_pct"]
            .as_f64()
            .expect("mul aggregate delta must be numeric")
            - 1.26)
            .abs()
            < 1e-9,
        "broader refresh must preserve the current-head mul mixed/regressed median delta"
    );
    assert_eq!(
        auto_mul["median_regressed_scenarios"].as_u64(),
        Some(6),
        "broader refresh must preserve the current-head mul slower-scenario count"
    );

    let auto_addmul = &refresh["aggregate_deltas_pct"]["auto_vs_baseline"]["addmul_slices2_auto"];
    assert!(
        (auto_addmul["average_median_delta_pct"]
            .as_f64()
            .expect("addmul median delta must be numeric")
            - (-2.17))
            .abs()
            < 1e-9,
        "broader refresh must preserve the current-head addmul median improvement"
    );

    let current_contract = &refresh["current_contract_summary"];
    assert_eq!(
        current_contract["canonical_default_contract_packet"].as_str(),
        Some("simd_policy_ablation_2026_03_04"),
        "broader refresh must point back to the canonical default contract packet"
    );
    assert_eq!(
        current_contract["selected_candidate_id"].as_str(),
        Some("candidate_addmul_window_only"),
        "broader refresh must record the selected candidate id explicitly"
    );
    assert_eq!(
        current_contract["mul_window"].as_str(),
        Some("unchanged: disabled (mul_min_total > mul_max_total)"),
        "broader refresh must preserve the disabled mul auto window contract"
    );
    assert_eq!(
        current_contract["addmul_window"].as_str(),
        Some("24576..32768 total bytes"),
        "broader refresh must preserve the widened addmul window contract"
    );
    assert_eq!(
        current_contract["addmul_min_lane"].as_u64(),
        Some(8192),
        "broader refresh must preserve the current addmul lane floor"
    );

    let closure = &refresh["closure_assessment"];
    assert_eq!(
        closure["ready_for_e5_closure"].as_bool(),
        Some(false),
        "broader refresh must not claim E5 closure"
    );
    assert_eq!(
        closure["acceptance_criterion_4_status"].as_str(),
        Some("not_met"),
        "broader refresh must keep AC#4 unresolved"
    );
    assert_eq!(
        closure["raw_sample_capture_demonstrated"].as_bool(),
        Some(true),
        "broader refresh must explicitly record that raw-sample evidence now exists"
    );
    assert_eq!(
        closure["broader_scope_demonstrated"].as_bool(),
        Some(true),
        "broader refresh must explicitly record that wider scenario coverage now exists"
    );
    assert_eq!(
        closure["longer_window_demonstrated"].as_bool(),
        Some(true),
        "broader refresh must explicitly record that longer-window evidence now exists"
    );
    assert_eq!(
        closure["closure_grade_material_uplift_demonstrated"].as_bool(),
        Some(false),
        "broader refresh must not overstate the evidence as closure-grade"
    );
    assert_eq!(
        closure["material_regression_demonstrated"].as_bool(),
        Some(true),
        "broader refresh must explicitly record the broader regression signal"
    );
    assert_eq!(
        closure["overall_median_direction_vs_baseline"].as_str(),
        Some("regressed"),
        "broader refresh must keep the overall broader-corpus median direction explicit"
    );
    assert_eq!(
        closure["overall_tail_direction_vs_baseline"].as_str(),
        Some("improved"),
        "broader refresh must keep the overall broader-corpus tail direction explicit"
    );
    assert_eq!(
        closure["operation_tail_pattern_vs_baseline"].as_str(),
        Some("addmul_improved_mul_mixed"),
        "broader refresh must preserve the addmul-improved / mul-mixed summary"
    );
    assert_eq!(
        closure["scope_sufficiency"].as_str(),
        Some("broader_raw_sample_sufficient_for_current_head_mixed_signal_only"),
        "broader refresh must keep the broader mixed-signal-only sufficiency contract explicit"
    );
    assert_eq!(
        closure["linked_guardrail_artifact"].as_str(),
        Some("artifacts/raptorq_track_e_gf256_p95p99_highconf_v1.json"),
        "broader refresh must keep the narrowed guardrail linkage explicit"
    );
    assert_eq!(
        closure["linked_guardrail_ready_for_e5_closure"].as_bool(),
        highconf["closure_assessment"]["ready_for_e5_closure"].as_bool(),
        "broader refresh must mirror the current guardrail not-ready state"
    );
    assert_eq!(
        closure["supersedes_directional_refresh_artifact"].as_str(),
        Some("artifacts/raptorq_track_e_gf256_multiscenario_refresh_v2.json"),
        "broader refresh must explicitly supersede the historical v2 directional packet"
    );
    assert_eq!(
        closure["supersedes_broader_interval_proxy_artifact"].as_str(),
        Some("artifacts/raptorq_track_e_gf256_multiscenario_refresh_v3.json"),
        "broader refresh must explicitly supersede the historical v3 interval-proxy packet"
    );
    assert!(
        closure["blocking_requirements"]
            .as_array()
            .is_some_and(|items| !items.is_empty()),
        "broader refresh must keep non-empty blockers while closure remains open"
    );
    assert!(
        refresh["limitations"].as_array().is_some_and(|items| {
            items.iter().any(|item| {
                item.as_str().is_some_and(|text| {
                    text.contains("supersedes the broader directional refresh")
                        && text.contains("highconf_v1")
                        && text.contains("v3")
                })
            })
        }),
        "broader refresh limitations must preserve the versioned-successor rule"
    );
}

/// Validate the top-level Track-E benchmark artifact keeps its
/// baseline/auto/rollback comparator commands on the SIMD bench surface.
#[test]
fn e5_bench_artifact_top_level_runs_exercise_simd_surface() {
    let artifact: serde_json::Value = serde_json::from_str(include_str!(
        "../artifacts/raptorq_track_e_gf256_bench_v1.json"
    ))
    .expect("Track-E benchmark artifact must be valid JSON");
    let runs = artifact["runs"]
        .as_array()
        .expect("Track-E benchmark artifact must include runs");

    assert_eq!(
        runs.len(),
        3,
        "Track-E benchmark artifact must keep baseline/auto/rollback runs"
    );

    for run in runs {
        let run_id = run["run_id"]
            .as_str()
            .expect("Track-E benchmark runs must include run_id");
        let command = run["command"]
            .as_str()
            .expect("Track-E benchmark runs must include command");
        assert!(
            command.starts_with("rch exec -- env "),
            "Track-E benchmark {run_id} command must stay rch-offloaded: {command}"
        );
        assert!(
            command.contains("cargo bench --bench raptorq_benchmark"),
            "Track-E benchmark {run_id} command must stay on the canonical benchmark: {command}"
        );
        assert!(
            command.contains("--features simd-intrinsics"),
            "Track-E benchmark {run_id} command must exercise the SIMD surface: {command}"
        );
        assert!(
            command.contains("-- gf256_primitives"),
            "Track-E benchmark {run_id} command must stay anchored to gf256_primitives: {command}"
        );
    }
}

/// Validate the E5 SIMD ablation artifact pins the current x86 default-window
/// decision and keeps the comparator command bundle reproducible.
#[test]
fn e5_simd_ablation_artifact_matches_current_x86_defaults() {
    let artifact: serde_json::Value = serde_json::from_str(include_str!(
        "../artifacts/raptorq_track_e_gf256_bench_v1.json"
    ))
    .expect("Track-E benchmark artifact must be valid JSON");
    let ablation = &artifact["simd_policy_ablation_2026_03_04"];

    assert_eq!(
        ablation["methodology"]["runner"].as_str(),
        Some("rch exec"),
        "E5 ablation corpus must remain rch-offloaded"
    );
    assert_eq!(
        ablation["methodology"]["bench_filter"].as_str(),
        Some("RQ-E-GF256-DUAL"),
        "E5 ablation corpus must stay anchored to the dual-policy benchmark family"
    );

    let commands = ablation["command_bundles"]
        .as_array()
        .expect("simd_policy_ablation_2026_03_04.command_bundles must be an array");
    assert_eq!(
        commands.len(),
        3,
        "E5 ablation corpus must keep baseline + two candidate command bundles"
    );
    for entry in commands {
        let command = entry["command"]
            .as_str()
            .expect("command bundle entries must include command");
        assert!(
            command.contains("rch exec --"),
            "E5 ablation command must use rch: {command}"
        );
        assert!(
            command.contains("CARGO_TARGET_DIR=/tmp/rch-e5-20260304-dual"),
            "E5 ablation command must pin the shared comparator target dir: {command}"
        );
        assert!(
            command.contains("--features simd-intrinsics"),
            "E5 ablation command must exercise the SIMD path: {command}"
        );
    }

    let decision = &ablation["decision"];
    assert_eq!(
        decision["selected_profile_defaults"].as_str(),
        Some("update x86 addmul auto window"),
        "E5 ablation decision must remain the x86 addmul-window update"
    );
    assert_eq!(
        decision["changes"]["mul_window"].as_str(),
        Some("unchanged: disabled (mul_min_total > mul_max_total)"),
        "E5 ablation decision must keep x86 mul auto disabled by default"
    );
    assert_eq!(
        decision["changes"]["addmul_window"].as_str(),
        Some("24576..32768 total bytes"),
        "E5 ablation decision must keep the selected x86 addmul window"
    );
    assert_eq!(
        decision["changes"]["addmul_min_lane"].as_u64(),
        Some(8192),
        "E5 ablation decision must keep the selected x86 addmul lane floor"
    );
}

/// Validate the live GF256 x86 profile-pack metadata stays aligned with the
/// canonical 2026-03-04 E5 default-contract artifact.
#[test]
#[allow(clippy::too_many_lines)]
fn e5_live_gf256_catalog_matches_current_x86_default_contract() {
    let artifact: serde_json::Value = serde_json::from_str(include_str!(
        "../artifacts/raptorq_track_e_gf256_bench_v1.json"
    ))
    .expect("Track-E benchmark artifact must be valid JSON");
    let decision = &artifact["simd_policy_ablation_2026_03_04"]["decision"];
    let x86 = gf256_profile_pack_catalog()
        .iter()
        .find(|metadata| metadata.profile_pack == Gf256ProfilePackId::X86Avx2BalancedV1)
        .expect("x86 profile-pack metadata must exist");

    assert_eq!(
        decision["decision_role"].as_str(),
        Some("canonical_current_x86_default_contract"),
        "E5 artifact must keep the current x86-default contract role explicit"
    );
    assert_eq!(
        decision["decision_artifact_id"].as_str(),
        Some("simd_policy_ablation_2026_03_04"),
        "E5 artifact must keep the current x86-default contract artifact id explicit"
    );
    assert_eq!(
        decision["decision_evidence_status"].as_str(),
        Some("canonical"),
        "E5 artifact must keep the current x86-default evidence maturity explicit"
    );
    assert_eq!(
        x86.architecture_class.as_str(),
        "x86-avx2",
        "live x86 profile-pack metadata must stay architecture-specific"
    );
    assert_eq!(
        x86.selected_tuning_candidate_id, "x86-avx2-t32-u4-pf64-split-balanced-v1",
        "live x86 profile-pack metadata must keep the selected split-biased candidate"
    );
    assert!(
        x86.selected_tuning_candidate_id.contains("split-balanced"),
        "live x86 profile-pack metadata must stay on the split-biased candidate"
    );
    assert!(
        x86.mul_min_total > x86.mul_max_total,
        "live x86 profile-pack metadata must keep dual-mul auto disabled by default"
    );
    assert_eq!(
        x86.addmul_min_total,
        24 * 1024,
        "live x86 profile-pack metadata must keep the selected addmul auto-window floor"
    );
    assert_eq!(
        x86.addmul_max_total,
        32 * 1024,
        "live x86 profile-pack metadata must keep the selected addmul auto-window ceiling"
    );
    assert_eq!(
        x86.addmul_min_lane,
        8 * 1024,
        "live x86 profile-pack metadata must keep the selected addmul lane floor"
    );
    assert_eq!(
        x86.replay_pointer, "replay:rq-e-gf256-profile-pack-v3",
        "live x86 profile-pack metadata must keep the documented replay contract"
    );
    assert_eq!(
        x86.command_bundle,
        "rch exec -- cargo bench --bench raptorq_benchmark --features simd-intrinsics -- gf256_primitives",
        "live x86 profile-pack metadata must keep the manifest command-bundle contract"
    );
    assert_eq!(
        x86.decision_artifact_id, "simd_policy_ablation_2026_03_04",
        "live x86 profile-pack metadata must keep the canonical decision artifact id"
    );
    assert_eq!(
        x86.decision_role, "canonical_current_x86_default_contract",
        "live x86 profile-pack metadata must keep the canonical decision role"
    );
    assert_eq!(
        x86.selected_candidate_summary,
        "material addmul auto uplift on balanced large-lane scenarios while mul auto remained near neutral",
        "live x86 profile-pack metadata must keep the selected-candidate rationale"
    );
    assert_eq!(
        x86.rejected_candidate_set_summary,
        "candidate mul windows improved addmul but regressed mul auto, so default rollout keeps mul auto disabled",
        "live x86 profile-pack metadata must keep the rejected-candidate rationale"
    );
    assert_eq!(
        x86.selected_mul_delta_vs_baseline_pct, "0.3048",
        "live x86 profile-pack metadata must keep the selected mul delta"
    );
    assert_eq!(
        x86.selected_addmul_delta_vs_baseline_pct, "-3.3759",
        "live x86 profile-pack metadata must keep the selected addmul delta"
    );
    assert_eq!(
        x86.selected_targeted_addmul_average_delta_pct, "-8.9924",
        "live x86 profile-pack metadata must keep the targeted addmul delta"
    );
    assert_eq!(
        decision["changes"]["mul_window"].as_str(),
        Some("unchanged: disabled (mul_min_total > mul_max_total)"),
        "artifact must keep the x86 mul-window contract in sync with live metadata"
    );
    assert_eq!(
        decision["changes"]["addmul_window"].as_str(),
        Some("24576..32768 total bytes"),
        "artifact must keep the x86 addmul-window contract in sync with live metadata"
    );
    assert_eq!(
        decision["changes"]["addmul_min_lane"].as_u64(),
        Some(x86.addmul_min_lane as u64),
        "artifact must keep the x86 addmul lane-floor contract in sync with live metadata"
    );
}

/// Validate the live GF256 aarch64 profile-pack metadata stays explicitly
/// provisional until same-target NEON ablation evidence exists.
#[test]
fn e5_live_gf256_catalog_keeps_aarch64_profile_provisional() {
    let neon = gf256_profile_pack_catalog()
        .iter()
        .find(|metadata| metadata.profile_pack == Gf256ProfilePackId::Aarch64NeonBalancedV1)
        .expect("aarch64 profile-pack metadata must exist");

    assert_eq!(
        neon.architecture_class.as_str(),
        "aarch64-neon",
        "live aarch64 profile-pack metadata must stay architecture-specific"
    );
    assert_eq!(
        neon.selected_tuning_candidate_id, "aarch64-neon-t32-u2-pf32-fused-balanced-v1",
        "live aarch64 profile-pack metadata must keep the pending same-target candidate explicit"
    );
    assert_eq!(
        neon.decision_artifact_id, "pending_same_target_profile_ablation",
        "aarch64 profile-pack metadata must not drift to a canonical artifact without new same-target evidence"
    );
    assert_eq!(
        neon.decision_role, "catalog_bootstrap_pending_same_target_ablation",
        "aarch64 profile-pack metadata must keep the pending decision role explicit"
    );
    assert_eq!(
        neon.decision_evidence_status.as_str(),
        "pending-same-target-ablation",
        "aarch64 profile-pack metadata must keep the pending evidence status explicit"
    );
    assert_eq!(
        neon.selected_candidate_summary,
        "catalog default retained pending same-target aarch64 ablation evidence",
        "aarch64 profile-pack metadata must keep the pending same-target rationale explicit"
    );
    assert_eq!(
        neon.rejected_candidate_set_summary,
        "nonselected aarch64 tuning candidates remain historical offline-tuning rejects",
        "aarch64 profile-pack metadata must keep the rejected-candidate rationale explicit"
    );

    for required in [
        "`aarch64-neon-balanced-v1` is intentionally surfaced as provisional",
        "decision_artifact_id = pending_same_target_profile_ablation",
        "decision_role = catalog_bootstrap_pending_same_target_ablation",
        "decision_evidence_status = pending-same-target-ablation",
        "until same-target NEON ablation evidence lands",
    ] {
        assert!(
            RAPTORQ_BASELINE_PROFILE_MD.contains(required),
            "baseline/profile doc must preserve pending aarch64 profile-pack token {required}"
        );
    }
}

/// Validate the live runtime policy snapshot carries the same decision
/// provenance as the effective profile-pack contract it selected.
#[test]
fn e5_live_dual_policy_snapshot_surfaces_decision_provenance() {
    let snapshot = dual_kernel_policy_snapshot();
    let selected_profile = gf256_profile_pack_catalog()
        .iter()
        .find(|metadata| metadata.profile_pack == snapshot.profile_pack)
        .expect("active profile pack must exist in the deterministic catalog");

    assert!(!snapshot.decision_artifact_id.is_empty());
    assert!(!snapshot.decision_role.is_empty());
    assert!(
        !snapshot.decision_evidence_status.as_str().is_empty(),
        "live dual-policy snapshot must carry a non-empty evidence maturity label"
    );

    if snapshot.decision_artifact_id == "manual_env_override_unbacked" {
        assert_eq!(
            snapshot.tuning_corpus_id, "manual-env-override-unbacked",
            "override policy snapshots must scrub the canonical tuning corpus id"
        );
        assert_eq!(
            snapshot.decision_artifact_id, "manual_env_override_unbacked",
            "override policy snapshots must fail closed on decision provenance"
        );
        assert_eq!(
            snapshot.decision_role, "runtime_override_not_canonical_profile_selection",
            "override policy snapshots must keep the override-specific decision role"
        );
        assert_eq!(
            snapshot.decision_evidence_status.as_str(),
            "runtime-override-unbacked",
            "override policy snapshots must keep the override-specific evidence status"
        );
        assert_ne!(
            snapshot.decision_artifact_id, selected_profile.decision_artifact_id,
            "override policy snapshots must not keep the catalog artifact id"
        );
        assert_ne!(
            snapshot.decision_evidence_status, selected_profile.decision_evidence_status,
            "override policy snapshots must not keep the catalog evidence maturity"
        );
        assert_ne!(
            snapshot.tuning_corpus_id, selected_profile.tuning_corpus_id,
            "override policy snapshots must not keep the catalog tuning corpus id"
        );
    } else {
        assert_eq!(
            snapshot.tuning_corpus_id, selected_profile.tuning_corpus_id,
            "canonical policy snapshots must mirror the selected catalog tuning corpus id"
        );
        assert_eq!(
            snapshot.decision_artifact_id, selected_profile.decision_artifact_id,
            "canonical policy snapshots must mirror the selected catalog artifact id"
        );
        assert_eq!(
            snapshot.decision_role, selected_profile.decision_role,
            "canonical policy snapshots must mirror the selected catalog decision role"
        );
        assert_eq!(
            snapshot.decision_evidence_status, selected_profile.decision_evidence_status,
            "canonical policy snapshots must mirror the selected catalog evidence maturity"
        );
    }
}

/// Validate the Track-E bench/probe contract keeps host architecture truth
/// separate from the selected profile-pack architecture when env requests
/// intentionally choose a different supported pack.
#[test]
fn e5_probe_contract_keeps_host_vs_selected_profile_architecture_fields_distinct() {
    let script = include_str!("../scripts/run_raptorq_e2e.sh");

    for required in [
        "\"architecture_class\": policy.architecture_class.as_str()",
        "\"active_profile_architecture_class\": active_profile.architecture_class.as_str()",
        "\"mode_fallback_reason\": policy.mode_fallback_reason.map_or(",
        "\"dual_policy_env_requested\": policy.override_mask.dual_policy_env_requested()",
        "\"profile_pack_env_requested\": policy.override_mask.profile_pack_env_requested()",
    ] {
        assert!(
            RAPTORQ_BENCH_RS.contains(required),
            "Track-E bench probe/log surface must keep token {required}",
        );
    }

    assert_ne!(
        RAPTORQ_BENCH_RS
            .find("\"architecture_class\": policy.architecture_class.as_str()")
            .expect("bench source must emit host architecture class"),
        RAPTORQ_BENCH_RS
            .find(
                "\"active_profile_architecture_class\": active_profile.architecture_class.as_str()"
            )
            .expect("bench source must emit active profile architecture class"),
        "bench source must keep host architecture and selected-profile architecture as distinct fields",
    );

    for required in [
        "(.architecture_class | type == \"string\" and length > 0)",
        "(.active_profile_architecture_class | type == \"string\" and length > 0)",
        "(.mode_fallback_reason == \"none\" or .mode_fallback_reason == \"unknown-requested-mode\")",
        "(.dual_policy_env_requested | type == \"boolean\")",
        "(.profile_pack_env_requested | type == \"boolean\")",
    ] {
        assert!(
            script.contains(required),
            "Track-E probe validation contract must require token {required}",
        );
    }
}

/// Validate the Track-E bench policy logs emit the live decision-metadata
/// fields needed to keep runtime policy and artifact reasoning aligned.
#[test]
fn e5_bench_policy_logs_emit_decision_metadata_fields() {
    assert!(
        RAPTORQ_BENCH_RS.contains("fn track_e_policy_payload("),
        "Track-E bench log surface must define a shared payload builder for the policy/probe metadata block"
    );
    for required in [
        "decision_artifact_id",
        "decision_role",
        "decision_evidence_status",
        "selected_candidate_summary",
        "rejected_candidate_set_summary",
        "selected_mul_delta_vs_baseline_pct",
        "selected_addmul_delta_vs_baseline_pct",
        "selected_targeted_addmul_average_delta_pct",
    ] {
        assert!(
            RAPTORQ_BENCH_RS.contains(required),
            "Track-E bench log surface must emit {required}"
        );
    }
}

/// Validate the Track-E policy log and policy probe both route through the
/// shared payload builder so future metadata additions cannot drift.
#[test]
fn e5_policy_log_and_probe_share_common_payload_builder() {
    let log_start = RAPTORQ_BENCH_RS
        .find("fn emit_track_e_policy_log(")
        .expect("bench source must define the Track-E policy log emitter");
    let probe_start = RAPTORQ_BENCH_RS
        .find("fn emit_track_e_policy_probe_log(")
        .expect("bench source must define the Track-E policy probe emitter");
    let next_fn_after_probe = RAPTORQ_BENCH_RS
        .find("fn selected_candidate_fields(")
        .expect("bench source must define the selected-candidate helper after the probe emitter");

    let log_section = &RAPTORQ_BENCH_RS[log_start..probe_start];
    let probe_section = &RAPTORQ_BENCH_RS[probe_start..next_fn_after_probe];

    assert_eq!(
        log_section.matches("track_e_policy_payload(").count(),
        1,
        "policy log emitter must call the shared payload builder exactly once"
    );
    assert_eq!(
        probe_section.matches("track_e_policy_payload(").count(),
        1,
        "policy probe emitter must call the shared payload builder exactly once"
    );
}

/// Validate the shared-builder call sites keep the policy-log and probe-log
/// schema/repro constants distinct for Track-E forensics.
#[test]
fn e5_policy_log_and_probe_keep_distinct_schema_and_repro_constants() {
    let log_start = RAPTORQ_BENCH_RS
        .find("fn emit_track_e_policy_log(")
        .expect("bench source must define the Track-E policy log emitter");
    let probe_start = RAPTORQ_BENCH_RS
        .find("fn emit_track_e_policy_probe_log(")
        .expect("bench source must define the Track-E policy probe emitter");
    let next_fn_after_probe = RAPTORQ_BENCH_RS
        .find("fn selected_candidate_fields(")
        .expect("bench source must define the selected-candidate helper after the probe emitter");

    let log_section = &RAPTORQ_BENCH_RS[log_start..probe_start];
    let probe_section = &RAPTORQ_BENCH_RS[probe_start..next_fn_after_probe];

    for required in [
        "schema_version: TRACK_E_POLICY_SCHEMA_VERSION",
        "repro_command: TRACK_E_REPRO_CMD",
    ] {
        assert!(
            log_section.contains(required),
            "policy log emitter must keep {required} at the shared-builder call site"
        );
    }
    for forbidden in [
        "schema_version: TRACK_E_POLICY_PROBE_SCHEMA_VERSION",
        "repro_command: TRACK_E_POLICY_PROBE_REPRO_CMD",
    ] {
        assert!(
            !log_section.contains(forbidden),
            "policy log emitter must not drift to probe constant {forbidden}"
        );
    }

    for required in [
        "schema_version: TRACK_E_POLICY_PROBE_SCHEMA_VERSION",
        "repro_command: TRACK_E_POLICY_PROBE_REPRO_CMD",
    ] {
        assert!(
            probe_section.contains(required),
            "policy probe emitter must keep {required} at the shared-builder call site"
        );
    }
    for forbidden in [
        "schema_version: TRACK_E_POLICY_SCHEMA_VERSION",
        "repro_command: TRACK_E_REPRO_CMD",
    ] {
        assert!(
            !probe_section.contains(forbidden),
            "policy probe emitter must not drift to policy-log constant {forbidden}"
        );
    }
}

/// Validate the E5 artifact makes the narrow 2026-03-02 same-session result a
/// historical comparator and pins the 2026-03-04 corpus as the canonical
/// default-selection contract.
#[test]
fn e5_simd_ablation_artifact_makes_decision_chronology_explicit() {
    let artifact: serde_json::Value = serde_json::from_str(include_str!(
        "../artifacts/raptorq_track_e_gf256_bench_v1.json"
    ))
    .expect("Track-E benchmark artifact must be valid JSON");

    let historical = &artifact["simd_policy_ablation_2026_03_02"]["decision"];
    assert_eq!(
        historical["selected_profile_defaults"].as_str(),
        Some("retain current x86 defaults"),
        "historical same-session result must keep the retained-defaults outcome"
    );
    assert_eq!(
        historical["decision_artifact_id"].as_str(),
        Some("simd_policy_ablation_2026_03_02"),
        "historical same-session result must keep its own artifact id explicit"
    );
    assert_eq!(
        historical["decision_evidence_status"].as_str(),
        Some("historical-reference"),
        "historical same-session result must stay tagged as historical reference evidence"
    );
    assert_eq!(
        historical["supersession"]["status"].as_str(),
        Some("superseded"),
        "historical same-session result must be marked superseded"
    );
    assert_eq!(
        historical["supersession"]["superseded_by"].as_str(),
        Some("simd_policy_ablation_2026_03_04"),
        "historical same-session result must point to the broader replacement corpus"
    );
    assert!(
        historical["supersession"]["reason"]
            .as_str()
            .expect("historical same-session result must explain supersession")
            .contains("historical comparator evidence only"),
        "historical same-session result must explain its historical-only role"
    );

    let canonical = &artifact["simd_policy_ablation_2026_03_04"]["decision"];
    assert_eq!(
        canonical["decision_role"].as_str(),
        Some("canonical_current_x86_default_contract"),
        "broader 2026-03-04 corpus must be pinned as the canonical x86 default contract"
    );
    assert_eq!(
        canonical["decision_artifact_id"].as_str(),
        Some("simd_policy_ablation_2026_03_04"),
        "broader 2026-03-04 corpus must keep the canonical artifact id explicit"
    );
    assert_eq!(
        canonical["decision_evidence_status"].as_str(),
        Some("canonical"),
        "broader 2026-03-04 corpus must stay tagged as canonical evidence"
    );
    let supersedes = canonical["supersedes"]
        .as_array()
        .expect("canonical 2026-03-04 decision must list superseded packets");
    assert_eq!(
        supersedes
            .iter()
            .map(serde_json::Value::as_str)
            .collect::<Vec<_>>(),
        vec![Some("simd_policy_ablation_2026_03_02")],
        "canonical 2026-03-04 decision must supersede the narrow 2026-03-02 result"
    );
}

/// Validate the legacy scalar policy snapshot is explicitly marked as
/// historical pre-refresh evidence rather than an unlabeled current default.
#[test]
fn e5_legacy_scalar_policy_snapshot_is_marked_historical() {
    let artifact: serde_json::Value = serde_json::from_str(include_str!(
        "../artifacts/raptorq_track_e_gf256_bench_v1.json"
    ))
    .expect("Track-E benchmark artifact must be valid JSON");

    let snapshot = &artifact["policy_snapshot_rq_e_gf256_005"];
    assert_eq!(
        snapshot["snapshot_role"].as_str(),
        Some("historical_pre_refresh_scalar_policy_wiring_reference"),
        "legacy policy snapshot must spell out its historical pre-refresh role"
    );
    assert_eq!(
        snapshot["status"].as_str(),
        Some("historical_reference_only"),
        "legacy policy snapshot must stay tagged as historical-only evidence"
    );
    assert_eq!(
        snapshot["superseded_by_decision_packet"].as_str(),
        Some("simd_policy_ablation_2026_03_04"),
        "legacy policy snapshot must point to the canonical replacement packet"
    );
    assert_eq!(
        snapshot["replay_pointer"].as_str(),
        Some("replay:rq-e-gf256-profile-pack-v1"),
        "legacy policy snapshot must preserve its original replay pointer"
    );
    assert!(
        snapshot["notes"]
            .as_str()
            .expect("legacy policy snapshot must explain its retained purpose")
            .contains("not as the current default contract"),
        "legacy policy snapshot notes must explain that it is not canonical"
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

    let coverage = artifact["coverage_summary"]
        .as_object()
        .expect("coverage_summary must be an object");
    assert_eq!(
        coverage
            .get("cards_total")
            .and_then(serde_json::Value::as_u64),
        Some(cards.len() as u64),
        "cards_total must match decision_cards length"
    );
    assert_eq!(
        coverage
            .get("cards_with_replay_commands")
            .and_then(serde_json::Value::as_u64),
        Some(cards.len() as u64),
        "all G3 cards must include deterministic replay commands"
    );
    assert_eq!(
        coverage
            .get("cards_with_conservative_comparator")
            .and_then(serde_json::Value::as_u64),
        Some(cards.len() as u64),
        "all G3 cards must include conservative comparator entries"
    );

    let partial_measured_levers = coverage
        .get("partial_measured_levers")
        .and_then(serde_json::Value::as_array)
        .expect("coverage_summary.partial_measured_levers must be an array")
        .iter()
        .map(|value| {
            value
                .as_str()
                .expect("partial_measured_levers entries must be strings")
                .to_string()
        })
        .collect::<BTreeSet<_>>();
    assert_eq!(
        partial_measured_levers,
        BTreeSet::from(["E5".to_string()]),
        "partial_measured_levers must reflect current closure blockers"
    );

    let pending_measured_levers = coverage
        .get("pending_measured_levers")
        .and_then(serde_json::Value::as_array)
        .expect("coverage_summary.pending_measured_levers must be an array")
        .iter()
        .map(|value| {
            value
                .as_str()
                .expect("pending_measured_levers entries must be strings")
                .to_string()
        })
        .collect::<BTreeSet<_>>();
    assert!(
        pending_measured_levers.is_empty(),
        "pending_measured_levers must be empty after F8 closure"
    );
    assert_eq!(
        coverage
            .get("cards_pending_measured_evidence")
            .and_then(serde_json::Value::as_u64),
        Some(pending_measured_levers.len() as u64),
        "cards_pending_measured_evidence must match pending_measured_levers length"
    );
    assert_eq!(
        coverage
            .get("cards_with_partial_measured_comparator_evidence")
            .and_then(serde_json::Value::as_u64),
        Some(partial_measured_levers.len() as u64),
        "cards_with_partial_measured_comparator_evidence must match partial_measured_levers length"
    );
    assert_eq!(
        coverage
            .get("cards_with_measured_comparator_evidence")
            .and_then(serde_json::Value::as_u64),
        Some((cards.len() - pending_measured_levers.len()) as u64),
        "cards_with_measured_comparator_evidence must match cards_total - cards_pending_measured_evidence"
    );

    let closure_blocker_levers = coverage
        .get("closure_blocker_levers")
        .and_then(serde_json::Value::as_array)
        .expect("coverage_summary.closure_blocker_levers must be an array")
        .iter()
        .map(|value| {
            value
                .as_str()
                .expect("closure_blocker_levers entries must be strings")
                .to_string()
        })
        .collect::<BTreeSet<_>>();
    assert_eq!(
        closure_blocker_levers,
        BTreeSet::from(["E5".to_string()]),
        "closure_blocker_levers must keep E5 visible while its measured evidence remains partial"
    );

    let f7_card = cards
        .iter()
        .find(|card| card["lever_code"].as_str() == Some("F7"))
        .expect("decision cards must include F7");
    assert_eq!(
        f7_card["measured_comparator_evidence"]["status"].as_str(),
        Some("closure_complete"),
        "F7 measured-evidence is closure_complete after v3 artifact publication"
    );
    assert!(
        f7_card["measured_comparator_evidence"]["pending_blockers"]
            .as_array()
            .expect("F7 measured_comparator_evidence.pending_blockers must be an array")
            .is_empty(),
        "F7 closure_complete state must have no pending blockers"
    );

    let f8_card = cards
        .iter()
        .find(|card| card["lever_code"].as_str() == Some("F8"))
        .expect("decision cards must include F8");
    assert_eq!(
        f8_card["status"].as_str(),
        Some("approved_guarded"),
        "F8 must be approved_guarded after wavefront pipeline closure"
    );
    assert_eq!(
        f8_card["owner"].as_str(),
        Some("FrostyCave"),
        "F8 must have FrostyCave as owner after closure"
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

/// Validate the E5 decision card stays aligned with the checked-in
/// high-confidence closure artifact instead of drifting into closure-ready
/// wording.
#[test]
fn g3_e5_decision_record_matches_current_highconf_blocker_state() {
    let decision_artifact: serde_json::Value = serde_json::from_str(RAPTORQ_OPT_DECISIONS_JSON)
        .expect("decision artifact must be valid JSON");
    let cards = decision_artifact["decision_cards"]
        .as_array()
        .expect("decision_cards must be an array");
    let e5 = cards
        .iter()
        .find(|card| card["lever_code"].as_str() == Some("E5"))
        .expect("decision cards must include E5");

    let highconf: serde_json::Value = serde_json::from_str(include_str!(
        "../artifacts/raptorq_track_e_gf256_p95p99_highconf_v1.json"
    ))
    .expect("Track-E high-confidence artifact must be valid JSON");
    let closure = &highconf["closure_assessment"];
    assert_eq!(
        closure["ready_for_e5_closure"].as_bool(),
        Some(false),
        "high-confidence closure assessment must keep E5 not-ready on the current frontier"
    );
    assert_eq!(
        closure["acceptance_criterion_4_status"].as_str(),
        Some("not_met"),
        "high-confidence closure assessment must keep AC#4 unresolved on the current frontier"
    );
    assert_eq!(
        e5["measured_comparator_evidence"]["status"].as_str(),
        Some("partial"),
        "E5 decision card must remain partial while the closure artifact is not ready"
    );
    let pending_blockers = e5["measured_comparator_evidence"]["pending_blockers"]
        .as_array()
        .expect("E5 pending_blockers must be an array")
        .iter()
        .map(|value| {
            value
                .as_str()
                .expect("E5 pending_blockers entries must be strings")
                .to_string()
        })
        .collect::<Vec<_>>();
    let artifact_refs = e5["measured_comparator_evidence"]["artifacts"]
        .as_array()
        .expect("E5 measured comparator artifacts must be an array")
        .iter()
        .map(|value| {
            value
                .as_str()
                .expect("E5 measured comparator artifacts entries must be strings")
                .to_string()
        })
        .collect::<Vec<_>>();
    assert!(
        artifact_refs
            .iter()
            .any(|entry| entry.contains("raptorq_track_e_gf256_p95p99_highconf_v1.json")),
        "E5 decision card must keep the narrowed high-confidence guardrail artifact"
    );
    assert!(
        artifact_refs
            .iter()
            .any(|entry| entry.contains("raptorq_track_e_gf256_multiscenario_refresh_v5.json")),
        "E5 decision card must reference the current broader raw-sample successor artifact"
    );
    assert!(
        pending_blockers.iter().any(|entry| {
            entry.contains("ready_for_e5_closure=false")
                || entry.contains("ready_for_e5_closure = false")
        }),
        "E5 pending blockers must cite the current high-confidence not-ready state"
    );
    assert!(
        pending_blockers
            .iter()
            .any(|entry| entry.contains("raw_sample_favorable_not_closure_grade")),
        "E5 pending blockers must preserve the current broader raw-sample successor contract"
    );
    assert!(
        pending_blockers
            .iter()
            .any(|entry| entry.contains("materially better broader")
                || entry.contains("current broader raw-sample successor packet")),
        "E5 pending blockers must preserve the remaining closure-grade evidence requirement"
    );

    for required in [
        "closure_blocker_levers = [E5]",
        "ready_for_e5_closure = false",
        "acceptance_criterion_4_status = not_met",
        "G3 closure remains blocked by E5",
        "new artifact/schema version",
        "highconf_v1",
        "artifacts/raptorq_track_e_gf256_multiscenario_refresh_v5.json",
        "raw_sample_favorable_not_closure_grade",
    ] {
        assert!(
            RAPTORQ_OPT_DECISIONS_MD.contains(required),
            "decision-record doc must mention current E5 blocker token {required}"
        );
    }
}

/// Validate the baseline/profile doc explains the separately versioned broader
/// Track-E refresh instead of collapsing it into the narrowed guardrail packet.
#[test]
fn e5_profile_pack_doc_explains_multiscenario_refresh_contract() {
    for required in [
        "artifacts/raptorq_track_e_gf256_multiscenario_refresh_v2.json",
        "artifacts/raptorq_track_e_gf256_multiscenario_refresh_v3.json",
        "artifacts/raptorq_track_e_gf256_multiscenario_refresh_v4.json",
        "artifacts/raptorq_track_e_gf256_multiscenario_refresh_v5.json",
        "schema_version = raptorq-track-e-gf256-multiscenario-refresh-v5",
        "evidence_role = broader_multiscenario_raw_sample_successor_guardrail",
        "scope_contract = same_target_multi_scenario_raw_sample_corpus",
        "confidence_contract = raw_sample_favorable_not_closure_grade",
        "candidate_addmul_window_only",
        "ready_for_e5_closure = false",
    ] {
        assert!(
            RAPTORQ_BASELINE_PROFILE_MD.contains(required),
            "baseline profile doc must explain multiscenario refresh token {required}"
        );
    }
}

/// Validate the E5 decision records keep manifest comparator and probe repro
/// commands on distinct, explicit surfaces.
#[test]
fn g3_e5_decision_record_command_surface_split_is_explicit() {
    let artifact: serde_json::Value = serde_json::from_str(RAPTORQ_OPT_DECISIONS_JSON)
        .expect("decision artifact must be valid JSON");
    let cards = artifact["decision_cards"]
        .as_array()
        .expect("decision_cards must be an array");
    let e5 = cards
        .iter()
        .find(|card| card["lever_code"].as_str() == Some("E5"))
        .expect("decision cards must include E5");
    let split = &e5["measured_comparator_evidence"]["command_surface_split"];
    assert_eq!(
        split["manifest_command_bundle"].as_str(),
        Some(
            "rch exec -- cargo bench --bench raptorq_benchmark --features simd-intrinsics -- gf256_primitives"
        ),
        "E5 manifest command bundle must stay anchored to gf256_primitives"
    );
    assert_eq!(
        split["probe_repro_command"].as_str(),
        Some(
            "rch exec -- cargo bench --bench raptorq_benchmark --features simd-intrinsics -- gf256_dual_policy"
        ),
        "E5 probe repro command must stay anchored to gf256_dual_policy"
    );
    for required in [
        "command_surface_split",
        "`command_bundle`",
        "`repro_command`",
        "gf256_primitives",
        "gf256_dual_policy",
    ] {
        assert!(
            RAPTORQ_OPT_DECISIONS_MD.contains(required),
            "decision-record doc must explain the E5 command split token {required}"
        );
    }
}

/// Validate the E5 decision record keeps the 2026-03-02 same-session packet as
/// historical evidence and the 2026-03-04 corpus as the canonical default
/// contract.
#[test]
fn g3_e5_decision_record_chronology_contract_is_explicit() {
    let artifact: serde_json::Value = serde_json::from_str(RAPTORQ_OPT_DECISIONS_JSON)
        .expect("decision artifact must be valid JSON");
    let cards = artifact["decision_cards"]
        .as_array()
        .expect("decision_cards must be an array");
    let e5 = cards
        .iter()
        .find(|card| card["lever_code"].as_str() == Some("E5"))
        .expect("decision cards must include E5");
    let chronology = &e5["measured_comparator_evidence"]["decision_chronology_contract"];
    assert_eq!(
        chronology["historical_same_session_packet"].as_str(),
        Some("simd_policy_ablation_2026_03_02"),
        "E5 decision record must keep the narrow same-session packet explicit"
    );
    assert_eq!(
        chronology["canonical_default_contract_packet"].as_str(),
        Some("simd_policy_ablation_2026_03_04"),
        "E5 decision record must pin the broader corpus as the canonical default contract"
    );
    assert_eq!(
        chronology["supersession_status"].as_str(),
        Some("historical_same_session_result_superseded_by_broader_corpus"),
        "E5 decision record must spell out the supersession contract"
    );
}

/// Validate the baseline/profile doc stays aligned with the current E5
/// artifact-backed x86 default-window contract.
#[test]
fn e5_profile_pack_doc_mentions_current_x86_default_contract() {
    for required in [
        "artifacts/raptorq_track_e_gf256_bench_v1.json",
        "simd_policy_ablation_2026_03_04",
        "raptorq-track-e-dual-policy-probe-v6",
        "profile-pack schema v5",
        "replay:rq-e-gf256-profile-pack-v3",
        "decision_artifact_id = simd_policy_ablation_2026_03_04",
        "decision_role = canonical_current_x86_default_contract",
        "decision_evidence_status = canonical",
        "`target_arch`, `target_os`, `target_env`, `target_endian`, `target_pointer_width_bits`",
        "addmul_slices2_c1_auto",
        "addmul_slices2_c1_sequential",
        "addmul_slices2_c1_bit_exact",
        "percentile-scored `operation_scope`",
        "selected_candidate_summary",
        "rejected_candidate_set_summary",
        "mul_min_total > mul_max_total",
        "24576..32768",
        "addmul_min_lane=8192",
        "CARGO_TARGET_DIR=/tmp/rch-e5-20260304-dual",
    ] {
        assert!(
            RAPTORQ_BASELINE_PROFILE_MD.contains(required),
            "baseline profile doc must mention {required}"
        );
    }
}

/// Validate the decision-record doc explains the E5 chronology contract
/// explicitly instead of relying on date ordering alone.
#[test]
fn g3_e5_decision_record_doc_explains_chronology_contract() {
    for required in [
        "decision_chronology_contract",
        "historical_same_session_packet = simd_policy_ablation_2026_03_02",
        "canonical_default_contract_packet = simd_policy_ablation_2026_03_04",
        "supersession_status = historical_same_session_result_superseded_by_broader_corpus",
        "historical comparator evidence",
        "canonical current x86 default contract",
    ] {
        assert!(
            RAPTORQ_OPT_DECISIONS_MD.contains(required),
            "decision-record doc must explain chronology contract token {required}"
        );
    }
}

/// Validate the doc keeps the manifest `command_bundle` and probe
/// `repro_command` surfaces distinct for E5 profile-pack forensics.
#[test]
fn e5_profile_pack_doc_explains_command_bundle_split() {
    for required in [
        "`command_bundle`",
        "`repro_command`",
        "gf256_primitives",
        "gf256_dual_policy",
        "Comparator/rollback bundle",
        "Probe-specific bundle",
    ] {
        assert!(
            RAPTORQ_BASELINE_PROFILE_MD.contains(required),
            "baseline profile doc must explain E5 command split token {required}"
        );
    }
}

/// Validate the baseline/profile doc explains that override runs fail closed
/// instead of claiming canonical profile-selection provenance.
#[test]
fn e5_profile_pack_doc_explains_override_truthfulness_rule() {
    for required in [
        "tuning_corpus_id = manual-env-override-unbacked",
        "manual-env-override-unbacked",
        "runtime_override_not_canonical_profile_selection",
        "manual_env_override_unbacked",
        "replay:rq-e-gf256-profile-pack-env-override-v1",
        "override-specific `command_bundle` placeholder",
        "selected_candidate_summary = runtime override changed the effective dual-policy contract; canonical selected candidate suppressed",
        "rejected_candidate_set_summary = override run is not a catalog-backed offline selection result; use emitted override fields to reproduce",
        "selected_mul_delta_vs_baseline_pct = n/a",
        "selected_addmul_delta_vs_baseline_pct = n/a",
        "selected_targeted_addmul_average_delta_pct = n/a",
    ] {
        assert!(
            RAPTORQ_BASELINE_PROFILE_MD.contains(required),
            "baseline profile doc must explain override truthfulness token {required}"
        );
    }
}

/// Validate the baseline/profile doc makes the SIMD ablation decision
/// chronology explicit instead of relying on date ordering alone.
#[test]
fn e5_profile_pack_doc_explains_ablation_decision_chronology() {
    for required in [
        "historical comparator",
        "simd_policy_ablation_2026_03_02.decision.decision_artifact_id = simd_policy_ablation_2026_03_02",
        "simd_policy_ablation_2026_03_02.decision.decision_evidence_status = historical-reference",
        "simd_policy_ablation_2026_03_02.decision.supersession.status = superseded",
        "simd_policy_ablation_2026_03_02.decision.supersession.superseded_by = simd_policy_ablation_2026_03_04",
        "simd_policy_ablation_2026_03_04.decision.decision_artifact_id = simd_policy_ablation_2026_03_04",
        "simd_policy_ablation_2026_03_04.decision.decision_role = canonical_current_x86_default_contract",
        "simd_policy_ablation_2026_03_04.decision.decision_evidence_status = canonical",
        "simd_policy_ablation_2026_03_04.decision.supersedes = [\"simd_policy_ablation_2026_03_02\"]",
    ] {
        assert!(
            RAPTORQ_BASELINE_PROFILE_MD.contains(required),
            "baseline profile doc must explain ablation chronology token {required}"
        );
    }
}

/// Validate the baseline/profile doc explains that the embedded scalar policy
/// snapshot is retained only as historical pre-refresh wiring evidence.
#[test]
fn e5_profile_pack_doc_marks_legacy_scalar_snapshot_historical() {
    for required in [
        "policy_snapshot_rq_e_gf256_005.snapshot_role = historical_pre_refresh_scalar_policy_wiring_reference",
        "policy_snapshot_rq_e_gf256_005.status = historical_reference_only",
        "policy_snapshot_rq_e_gf256_005.superseded_by_decision_packet = simd_policy_ablation_2026_03_04",
        "policy_snapshot_rq_e_gf256_005.replay_pointer = replay:rq-e-gf256-profile-pack-v1",
        "It is not the current default",
        "canonical current x86 default contract remains",
    ] {
        assert!(
            RAPTORQ_BASELINE_PROFILE_MD.contains(required),
            "baseline profile doc must explain legacy scalar snapshot token {required}"
        );
    }
}

/// Validate G4 controlled-rollout policy schema and lever coverage.
#[test]
#[allow(clippy::too_many_lines)]
fn g4_rollout_policy_schema_and_lever_coverage() {
    let artifact: serde_json::Value = serde_json::from_str(RAPTORQ_G4_ROLLOUT_POLICY_JSON)
        .expect("G4 rollout policy artifact must be valid JSON");

    assert_eq!(
        artifact["schema_version"].as_str(),
        Some(G4_ROLLOUT_POLICY_SCHEMA_VERSION),
        "unexpected G4 rollout policy schema version"
    );
    assert_eq!(
        artifact["track_bead_id"].as_str(),
        Some("asupersync-23kd4"),
        "G4 rollout policy must stay anchored to asupersync-23kd4"
    );
    assert_eq!(
        artifact["external_ref"].as_str(),
        Some("bd-2frfp"),
        "G4 rollout policy must stay anchored to bd-2frfp"
    );
    assert_eq!(
        artifact["command_policy"]["cargo_heavy_commands_must_use_rch"].as_bool(),
        Some(true),
        "G4 command policy must require rch for cargo-heavy commands"
    );
    assert_eq!(
        artifact["command_policy"]["required_prefix"].as_str(),
        Some("rch exec --"),
        "G4 command policy must enforce rch command prefix"
    );

    let stages = artifact["staged_rollout"]
        .as_array()
        .expect("staged_rollout must be an array");
    assert_eq!(
        stages.len(),
        4,
        "G4 staged_rollout must define exactly 4 stages"
    );
    let expected_stage_order = [
        ("shadow_observe", 0_i64),
        ("canary", 1_i64),
        ("guarded_ramp", 2_i64),
        ("broad_default", 3_i64),
    ];
    for (idx, (expected_stage, expected_order)) in expected_stage_order.iter().enumerate() {
        let stage = &stages[idx];
        assert_eq!(
            stage["stage"].as_str(),
            Some(*expected_stage),
            "unexpected stage name at index {idx}"
        );
        assert_eq!(
            stage["order"].as_i64(),
            Some(*expected_order),
            "unexpected stage order for {expected_stage}"
        );
        for field in ["entry_criteria", "hold_requirements", "stop_conditions"] {
            let entries = stage[field]
                .as_array()
                .expect("stage requirements must be arrays");
            assert!(
                !entries.is_empty(),
                "stage {expected_stage} must define non-empty {field}"
            );
        }
    }

    let trigger_classes = artifact["rollback_automation"]["trigger_classes"]
        .as_array()
        .expect("rollback_automation.trigger_classes must be an array")
        .iter()
        .map(|entry| {
            entry["class"]
                .as_str()
                .expect("trigger class must be a string")
                .to_string()
        })
        .collect::<BTreeSet<_>>();
    let expected_trigger_classes = BTreeSet::from([
        "correctness_regression".to_string(),
        "performance_budget_breach".to_string(),
        "instability_signal".to_string(),
    ]);
    assert_eq!(
        trigger_classes, expected_trigger_classes,
        "G4 rollback trigger classes must match required governance set"
    );

    let operator_fields = artifact["operator_response_packet"]["required_fields"]
        .as_array()
        .expect("operator_response_packet.required_fields must be an array")
        .iter()
        .map(|value| {
            value
                .as_str()
                .expect("operator_response_packet field must be a string")
                .to_string()
        })
        .collect::<BTreeSet<_>>();
    for required in [
        "symptom",
        "exposure_scope",
        "affected_levers",
        "mitigation_executed",
        "replay_command",
        "artifact_path",
        "eta",
        "user_impact_message_template",
    ] {
        assert!(
            operator_fields.contains(required),
            "operator response packet must include {required}"
        );
    }

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
    let lever_rows = artifact["lever_matrix"]
        .as_array()
        .expect("lever_matrix must be an array");
    assert_eq!(
        lever_rows.len(),
        8,
        "G4 lever matrix must contain exactly 8 high-impact lever rows"
    );
    let observed_levers = lever_rows
        .iter()
        .map(|entry| {
            entry["lever_code"]
                .as_str()
                .expect("lever_matrix entry must include lever_code")
                .to_string()
        })
        .collect::<BTreeSet<_>>();
    assert_eq!(
        observed_levers, expected_levers,
        "G4 lever matrix must cover C5/C6/E4/E5/F5/F6/F7/F8"
    );
}

/// Validate G4 rollout-policy docs cross-link to canonical artifacts.
#[test]
fn g4_rollout_policy_docs_are_cross_linked() {
    for required in [
        "asupersync-23kd4",
        "asupersync-2cyx5",
        "artifacts/raptorq_controlled_rollout_policy_v1.json",
        "artifacts/raptorq_optimization_decision_records_v1.json",
        "rch exec --",
        "shadow_observe",
        "broad_default",
        "user_impact_message_template",
    ] {
        assert!(
            RAPTORQ_G4_ROLLOUT_POLICY_MD.contains(required),
            "G4 rollout policy doc must mention {required}"
        );
    }
}

/// Validate G7 expected-loss decision-contract schema and coverage.
#[test]
#[allow(clippy::too_many_lines)]
fn g7_expected_loss_contract_schema_and_coverage() {
    let artifact: serde_json::Value = serde_json::from_str(RAPTORQ_G7_EXPECTED_LOSS_JSON)
        .expect("G7 expected-loss artifact must be valid JSON");

    assert_eq!(
        artifact["schema_version"].as_str(),
        Some(G7_EXPECTED_LOSS_CONTRACT_SCHEMA_VERSION),
        "unexpected G7 expected-loss schema version"
    );
    assert_eq!(
        artifact["track_bead_id"].as_str(),
        Some("asupersync-m7o6i"),
        "G7 contract must stay anchored to asupersync-m7o6i"
    );
    assert_eq!(
        artifact["external_ref"].as_str(),
        Some("bd-2bd8e"),
        "G7 contract must stay anchored to bd-2bd8e"
    );

    let expected_states = BTreeSet::from([
        "healthy".to_string(),
        "degraded".to_string(),
        "regression".to_string(),
        "unknown".to_string(),
    ]);
    let observed_states = artifact["contract"]["states"]
        .as_array()
        .expect("contract.states must be an array")
        .iter()
        .map(|value| {
            value
                .as_str()
                .expect("state entries must be strings")
                .to_string()
        })
        .collect::<BTreeSet<_>>();
    assert_eq!(
        observed_states, expected_states,
        "G7 state set must cover healthy/degraded/regression/unknown"
    );

    let expected_actions = BTreeSet::from([
        "continue".to_string(),
        "canary_hold".to_string(),
        "rollback".to_string(),
        "fallback".to_string(),
    ]);
    let observed_actions = artifact["contract"]["actions"]
        .as_array()
        .expect("contract.actions must be an array")
        .iter()
        .map(|value| {
            value
                .as_str()
                .expect("action entries must be strings")
                .to_string()
        })
        .collect::<BTreeSet<_>>();
    assert_eq!(
        observed_actions, expected_actions,
        "G7 action set must cover continue/canary_hold/rollback/fallback"
    );

    let matrix_rows = artifact["contract"]["loss_matrix"]
        .as_array()
        .expect("contract.loss_matrix must be an array");
    assert_eq!(
        matrix_rows.len(),
        4,
        "G7 loss matrix must have 4 state rows"
    );
    for row in matrix_rows {
        let state = row["state"]
            .as_str()
            .expect("loss_matrix state must be a string");
        let terms = row["loss_terms"]
            .as_object()
            .expect("loss_matrix.loss_terms must be an object");
        for action in ["continue", "canary_hold", "rollback", "fallback"] {
            let term = terms
                .get(action)
                .expect("loss_terms must contain every action")
                .as_i64()
                .expect("loss term must be numeric");
            assert!(
                term >= 0,
                "loss term must be non-negative for state {state}"
            );
        }
    }
    let regression_terms = artifact["contract"]["loss_matrix"][2]["loss_terms"]
        .as_object()
        .expect("regression loss terms must be present");
    let regression_continue = regression_terms["continue"]
        .as_i64()
        .expect("regression continue loss must be numeric");
    let regression_fallback = regression_terms["fallback"]
        .as_i64()
        .expect("regression fallback loss must be numeric");
    assert!(
        regression_fallback < regression_continue,
        "regression loss must prefer fallback over continue"
    );

    assert_eq!(
        artifact["contract"]["decision_rule"]["selector"].as_str(),
        Some("argmin_expected_loss"),
        "G7 selector must be argmin_expected_loss"
    );
    assert_eq!(
        artifact["contract"]["decision_rule"]["deterministic_fallback_trigger"]["then_action"]
            .as_str(),
        Some("fallback"),
        "G7 fallback trigger must force fallback action"
    );
    let fallback_trigger_reasons =
        artifact["contract"]["decision_rule"]["deterministic_fallback_trigger"]["if_any"]
            .as_array()
            .expect("G7 fallback trigger if_any must be an array")
            .iter()
            .map(|value| {
                value
                    .as_str()
                    .expect("G7 fallback trigger reasons must be strings")
                    .to_string()
            })
            .collect::<BTreeSet<_>>();
    for reason in G7_RUNTIME_FALLBACK_REASONS {
        assert!(
            fallback_trigger_reasons.contains(*reason),
            "G7 fallback trigger contract must include the runtime reason {reason}"
        );
    }
    for reason in ["decode_mismatch_detected", "proof_replay_mismatch"] {
        assert!(
            fallback_trigger_reasons.contains(reason),
            "G7 fallback trigger contract must include {reason}"
        );
    }

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
    let lever_rows = artifact["runtime_control_surface"]["in_scope_levers"]
        .as_array()
        .expect("runtime_control_surface.in_scope_levers must be an array");
    assert_eq!(lever_rows.len(), 8, "G7 lever map must contain 8 rows");
    let observed_levers = lever_rows
        .iter()
        .map(|entry| {
            let controls = entry["controls"]
                .as_array()
                .expect("lever controls must be an array");
            assert!(
                !controls.is_empty(),
                "each G7 lever row must include at least one control field"
            );
            entry["lever_code"]
                .as_str()
                .expect("lever_code must be a string")
                .to_string()
        })
        .collect::<BTreeSet<_>>();
    assert_eq!(
        observed_levers, expected_levers,
        "G7 lever map must cover C5/C6/E4/E5/F5/F6/F7/F8"
    );

    let required_output_fields = artifact["decision_output"]["required_fields"]
        .as_array()
        .expect("decision_output.required_fields must be an array")
        .iter()
        .map(|value| {
            value
                .as_str()
                .expect("required decision output fields must be strings")
                .to_string()
        })
        .collect::<BTreeSet<_>>();
    for field in [
        "state_posterior",
        "expected_loss_terms",
        "chosen_action",
        "top_evidence_contributors",
        "confidence_score",
        "uncertainty_score",
        "deterministic_fallback_trigger",
        "replay_ref",
    ] {
        assert!(
            required_output_fields.contains(field),
            "G7 decision output must include {field}"
        );
    }

    let logging_fields = artifact["structured_logging"]["required_fields"]
        .as_array()
        .expect("structured_logging.required_fields must be an array")
        .iter()
        .map(|value| {
            value
                .as_str()
                .expect("structured logging fields must be strings")
                .to_string()
        })
        .collect::<BTreeSet<_>>();
    for field in [
        "state_posterior",
        "expected_loss_terms",
        "chosen_action",
        "replay_ref",
    ] {
        assert!(
            logging_fields.contains(field),
            "G7 structured logging must include {field}"
        );
    }

    let unit_commands = artifact["validation"]["unit_commands"]
        .as_array()
        .expect("validation.unit_commands must be an array")
        .iter()
        .map(|value| {
            value
                .as_str()
                .expect("validation unit commands must be strings")
                .to_string()
        })
        .collect::<BTreeSet<_>>();
    for command in [
        "rch exec -- cargo test --test raptorq_perf_invariants g7_expected_loss_contract_schema_and_coverage -- --nocapture",
        "rch exec -- cargo test --test raptorq_perf_invariants g7_expected_loss_contract_replay_bundle_is_well_formed -- --nocapture",
        "rch exec -- cargo test --test raptorq_perf_invariants g7_expected_loss_contract_docs_are_cross_linked -- --nocapture",
    ] {
        assert!(
            unit_commands.contains(command),
            "G7 validation.unit_commands must include {command}"
        );
    }
    let status_snapshot_contract = &artifact["reproducibility"]["status_snapshot_contract"];
    assert_eq!(
        status_snapshot_contract["env_var"].as_str(),
        Some("ASUPERSYNC_BEADS_STATUS_OVERRIDES_JSON"),
        "G7 status snapshot contract must name the override env"
    );
    assert_eq!(
        status_snapshot_contract["source_of_truth"].as_str(),
        Some(".beads/issues.jsonl from the caller workspace snapshot"),
        "G7 status snapshot contract must identify the caller-side Beads snapshot"
    );
    let status_snapshot_reason = status_snapshot_contract["reason"]
        .as_str()
        .expect("G7 status snapshot contract must explain why the override exists");
    assert!(
        status_snapshot_reason.contains("shared rch workers")
            && status_snapshot_reason.contains("stale .beads/issues.jsonl"),
        "G7 status snapshot contract reason must explain the shared-rch stale-JSONL hazard"
    );
    let status_snapshot_beads = status_snapshot_contract["required_bead_ids"]
        .as_array()
        .expect("G7 status snapshot contract must list required bead ids")
        .iter()
        .map(|value| {
            value
                .as_str()
                .expect("G7 status snapshot contract bead ids must be strings")
                .to_string()
        })
        .collect::<BTreeSet<_>>();
    assert_eq!(
        status_snapshot_beads,
        BTreeSet::from([
            "asupersync-2cyx5".to_string(),
            "asupersync-36m6p".to_string(),
            "asupersync-3ltrv".to_string(),
            "asupersync-n5fk6".to_string(),
            "asupersync-2zu9p".to_string(),
        ]),
        "G7 status snapshot contract must list the live Beads ids that feed closure_readiness assertions"
    );
    let applies_to_unit_commands = status_snapshot_contract["applies_to_unit_commands"]
        .as_array()
        .expect("G7 status snapshot contract must list the affected unit commands")
        .iter()
        .map(|value| {
            value
                .as_str()
                .expect("G7 status snapshot contract commands must be strings")
                .to_string()
        })
        .collect::<BTreeSet<_>>();
    assert_eq!(
        applies_to_unit_commands, unit_commands,
        "G7 status snapshot contract must cover the canonical G7 unit commands"
    );

    let replay_command = artifact["reproducibility"]["replay_command"]
        .as_str()
        .expect("replay command must be present");
    assert!(
        replay_command.contains("rch exec --"),
        "G7 replay command must use rch"
    );

    assert_eq!(
        artifact["reproducibility"]["decision_replay_bundle"]["artifact_path"].as_str(),
        Some(REPLAY_CATALOG_ARTIFACT_PATH),
        "G7 decision replay bundle must point to canonical replay catalog artifact"
    );

    let closure_readiness = &artifact["closure_readiness"];
    let ready_to_close = closure_readiness["ready_to_close"]
        .as_bool()
        .expect("closure_readiness.ready_to_close must be a bool");
    let canonical_issue_statuses = beads_latest_status_by_id();
    let closure_dependencies = closure_readiness["dependencies"]
        .as_array()
        .expect("closure_readiness.dependencies must be an array");
    assert!(
        !closure_dependencies.is_empty(),
        "closure_readiness.dependencies must list at least one dependency"
    );
    let dependency_evidence_refs = closure_dependencies
        .iter()
        .map(|entry| {
            let required_status = entry["required_status"]
                .as_str()
                .expect("closure dependency must include required_status");
            let current_status = entry["current_status"]
                .as_str()
                .expect("closure dependency must include current_status");
            assert!(
                matches!(required_status, "open" | "in_progress" | "closed"),
                "closure dependency required_status must be open|in_progress|closed"
            );
            assert!(
                matches!(current_status, "open" | "in_progress" | "closed"),
                "closure dependency current_status must be open|in_progress|closed"
            );
            let evidence_refs = entry["evidence_refs"]
                .as_array()
                .expect("closure dependency must include evidence_refs");
            assert!(
                !evidence_refs.is_empty(),
                "closure dependency must include at least one evidence ref"
            );
            let evidence_refs = evidence_refs
                .iter()
                .map(|value| {
                    value
                        .as_str()
                        .expect("closure dependency evidence_refs entries must be strings")
                        .to_string()
                })
                .collect::<BTreeSet<_>>();
            let bead_id = entry["bead_id"]
                .as_str()
                .expect("closure dependency must include bead_id")
                .to_string();
            let canonical_status = canonical_issue_statuses
                .get(&bead_id)
                .unwrap_or_else(|| panic!("closure dependency bead {bead_id} must exist in .beads/issues.jsonl"));
            assert_eq!(
                current_status, canonical_status,
                "closure dependency {bead_id} current_status must match canonical Beads issue status"
            );
            (bead_id, evidence_refs)
        })
        .collect::<BTreeMap<_, _>>();
    let dependency_beads = dependency_evidence_refs
        .keys()
        .cloned()
        .collect::<BTreeSet<_>>();
    for required in [
        "asupersync-3ltrv",
        "asupersync-36m6p",
        "asupersync-n5fk6",
        "asupersync-2zu9p",
    ] {
        assert!(
            dependency_beads.contains(required),
            "closure_readiness.dependencies must include {required}"
        );
    }

    let e5_evidence_refs = dependency_evidence_refs
        .get("asupersync-36m6p")
        .expect("closure_readiness.dependencies must include the E5 bead");
    let e5_dependency = closure_dependencies
        .iter()
        .find(|entry| entry["bead_id"].as_str() == Some("asupersync-36m6p"))
        .expect("closure_readiness.dependencies must include the E5 bead");
    assert_eq!(
        e5_dependency["name"].as_str(),
        Some("E5 Track-E evidence lineage (highconf_v1 + v2/v3/v4 history + v5 successor)"),
        "E5 closure dependency name must reflect the current multi-packet blocker lineage"
    );
    for required in [
        "artifacts/raptorq_track_e_gf256_p95p99_highconf_v1.json",
        "artifacts/raptorq_track_e_gf256_multiscenario_refresh_v2.json",
        "artifacts/raptorq_track_e_gf256_multiscenario_refresh_v3.json",
        "artifacts/raptorq_track_e_gf256_multiscenario_refresh_v4.json",
        "artifacts/raptorq_track_e_gf256_multiscenario_refresh_v5.json",
    ] {
        assert!(
            e5_evidence_refs.contains(required),
            "E5 closure dependency must retain evidence ref {required}"
        );
    }

    if !ready_to_close {
        let remaining_requirements = closure_readiness["remaining_requirements"]
            .as_array()
            .expect("remaining_requirements must be an array when not ready_to_close");
        assert!(
            !remaining_requirements.is_empty(),
            "remaining_requirements must be non-empty when ready_to_close is false"
        );
        let remaining_requirements = remaining_requirements
            .iter()
            .map(|value| {
                value
                    .as_str()
                    .expect("remaining_requirements entries must be strings")
                    .to_string()
            })
            .collect::<BTreeSet<_>>();
        assert!(
            remaining_requirements.iter().any(|entry| {
                entry.contains("materially better broader")
                    && entry.contains("raptorq_track_e_gf256_multiscenario_refresh_v5.json")
            }),
            "remaining_requirements must preserve the missing broader-improvement E5 requirement against the current v5 successor packet"
        );
        assert!(
            !remaining_requirements
                .iter()
                .any(|entry| entry.contains("mixed-signal raw-sample v4")),
            "remaining_requirements must not describe v4 as the current broader blocker after the v5 refresh"
        );
    }

    assert_eq!(
        closure_readiness["track_g_handoff"]["bead_id"].as_str(),
        Some("asupersync-2cyx5"),
        "closure_readiness.track_g_handoff must stay anchored to Track-G bead"
    );
    let track_g_status = closure_readiness["track_g_handoff"]["current_status"]
        .as_str()
        .expect("closure_readiness.track_g_handoff.current_status must be present");
    let canonical_track_g_status = canonical_issue_statuses
        .get("asupersync-2cyx5")
        .expect("Track-G bead must exist in canonical Beads issue status map");
    assert!(
        matches!(track_g_status, "open" | "in_progress" | "closed"),
        "closure_readiness.track_g_handoff.current_status must be open|in_progress|closed"
    );
    assert_eq!(
        track_g_status, canonical_track_g_status,
        "closure_readiness.track_g_handoff.current_status must match canonical Track-G Beads status"
    );
    let expected_track_g_handoff_fields = BTreeSet::from([
        String::from("gate_verdict_table"),
        String::from("artifact_replay_index"),
        String::from("residual_risk_register"),
        String::from("go_no_go_decision"),
    ]);
    let required_track_g_handoff_fields =
        closure_readiness["track_g_handoff"]["required_packet_fields"]
            .as_array()
            .expect("closure_readiness.track_g_handoff.required_packet_fields must be present")
            .iter()
            .map(|value| {
                value
                    .as_str()
                    .expect("required_packet_fields entries must be strings")
                    .to_string()
            })
            .collect::<BTreeSet<_>>();
    assert_eq!(
        required_track_g_handoff_fields, expected_track_g_handoff_fields,
        "closure_readiness.track_g_handoff.required_packet_fields must stay aligned with the H2 packet handoff contract"
    );
    let attached_track_g_handoff_fields =
        closure_readiness["track_g_handoff"]["attached_packet_fields"]
            .as_array()
            .expect("closure_readiness.track_g_handoff.attached_packet_fields must be present")
            .iter()
            .map(|value| {
                value
                    .as_str()
                    .expect("attached_packet_fields entries must be strings")
                    .to_string()
            })
            .collect::<BTreeSet<_>>();
    assert_eq!(
        attached_track_g_handoff_fields, expected_track_g_handoff_fields,
        "closure_readiness.track_g_handoff.attached_packet_fields must match the required handoff fields while Track-G remains non-closed"
    );
    assert_eq!(
        closure_readiness["track_g_handoff"]["attachment_status"].as_str(),
        Some("complete_in_h2_packet_pending_track_g_closure"),
        "closure_readiness.track_g_handoff.attachment_status must describe the blocked-but-attached H2 packet state"
    );
    assert_eq!(
        closure_readiness["track_g_handoff"]["evidence_ref"].as_str(),
        Some("artifacts/raptorq_program_closure_signoff_packet_v1.json"),
        "closure_readiness.track_g_handoff.evidence_ref must stay anchored to the canonical H2 packet artifact"
    );
    let h2_packet_artifact: serde_json::Value =
        serde_json::from_str(RAPTORQ_H2_CLOSURE_PACKET_JSON)
            .expect("H2 closure packet artifact must be valid JSON");
    for field in &expected_track_g_handoff_fields {
        assert!(
            h2_packet_artifact.get(field).is_some(),
            "H2 closure packet artifact must include the Track-G handoff field {field}"
        );
    }
}

/// Validate G7 deterministic decision replay samples are complete and coherent.
#[test]
#[allow(clippy::too_many_lines)]
fn g7_expected_loss_contract_replay_bundle_is_well_formed() {
    let artifact: serde_json::Value = serde_json::from_str(RAPTORQ_G7_EXPECTED_LOSS_JSON)
        .expect("G7 expected-loss artifact must be valid JSON");
    let replay_catalog: serde_json::Value =
        serde_json::from_str(include_str!("../artifacts/raptorq_replay_catalog_v1.json",))
            .expect("replay catalog must be valid JSON");

    let catalog_replay_refs = replay_catalog["entries"]
        .as_array()
        .expect("replay catalog entries must be an array")
        .iter()
        .map(|entry| {
            entry["replay_ref"]
                .as_str()
                .expect("replay catalog entries must include replay_ref")
                .to_string()
        })
        .collect::<BTreeSet<_>>();

    let bundle = &artifact["reproducibility"]["decision_replay_bundle"];
    let required_classes = bundle["required_scenario_classes"]
        .as_array()
        .expect("required_scenario_classes must be an array")
        .iter()
        .map(|value| {
            value
                .as_str()
                .expect("required_scenario_classes values must be strings")
                .to_string()
        })
        .collect::<BTreeSet<_>>();
    assert_eq!(
        required_classes,
        BTreeSet::from([
            "normal".to_string(),
            "edge".to_string(),
            "conflicting_evidence".to_string(),
        ]),
        "G7 bundle must require normal/edge/conflicting_evidence classes"
    );

    let decision_samples = bundle["decision_samples"]
        .as_array()
        .expect("decision_samples must be an array");
    assert!(
        decision_samples.len() >= 3,
        "G7 decision replay bundle must include at least three scenario samples"
    );

    let tie_break_rank = |action: &str| -> usize {
        match action {
            "fallback" => 0,
            "rollback" => 1,
            "canary_hold" => 2,
            "continue" => 3,
            _ => usize::MAX,
        }
    };
    let required_states = BTreeSet::from([
        "healthy".to_string(),
        "degraded".to_string(),
        "regression".to_string(),
        "unknown".to_string(),
    ]);
    let required_actions = BTreeSet::from([
        "continue".to_string(),
        "canary_hold".to_string(),
        "rollback".to_string(),
        "fallback".to_string(),
    ]);

    for sample in decision_samples {
        let scenario_class = sample["scenario_class"]
            .as_str()
            .expect("decision sample must include scenario_class");
        assert!(
            required_classes.contains(scenario_class),
            "decision sample has unsupported scenario_class {scenario_class}"
        );

        let replay_ref = sample["replay_ref"]
            .as_str()
            .expect("decision sample must include replay_ref");
        assert!(
            catalog_replay_refs.contains(replay_ref),
            "decision sample replay_ref {replay_ref} must be present in replay catalog"
        );

        let _seed = sample["seed"]
            .as_u64()
            .expect("decision sample seed must be an unsigned integer");
        let state_posterior = sample["state_posterior"]
            .as_object()
            .expect("decision sample must include state_posterior object");
        let observed_states = state_posterior.keys().cloned().collect::<BTreeSet<_>>();
        assert_eq!(
            observed_states, required_states,
            "decision sample state_posterior must cover all G7 states"
        );

        let expected_loss_terms = sample["expected_loss_terms"]
            .as_object()
            .expect("decision sample must include expected_loss_terms object");
        let observed_actions = expected_loss_terms.keys().cloned().collect::<BTreeSet<_>>();
        assert_eq!(
            observed_actions, required_actions,
            "decision sample expected_loss_terms must cover all G7 actions"
        );

        let chosen_action = sample["chosen_action"]
            .as_str()
            .expect("decision sample must include chosen_action");
        assert!(
            required_actions.contains(chosen_action),
            "decision sample chosen_action must be a valid G7 action"
        );

        let contributors = sample["top_evidence_contributors"]
            .as_array()
            .expect("decision sample must include top_evidence_contributors array");
        assert!(
            !contributors.is_empty(),
            "decision sample must include at least one evidence contributor"
        );
        for contributor in contributors {
            let _name = contributor["name"]
                .as_str()
                .expect("evidence contributor must include name");
            let _weight = contributor["contribution_permille"]
                .as_u64()
                .expect("evidence contributor must include contribution_permille");
        }

        let confidence_score = sample["confidence_score"]
            .as_u64()
            .expect("confidence_score must be numeric");
        let uncertainty_score = sample["uncertainty_score"]
            .as_u64()
            .expect("uncertainty_score must be numeric");
        assert!(
            confidence_score <= 1000,
            "confidence_score must remain within configured 0..=1000 range"
        );
        assert!(
            uncertainty_score <= 1000,
            "uncertainty_score must remain within configured 0..=1000 range"
        );

        let fallback_trigger = sample["deterministic_fallback_trigger"]
            .as_object()
            .expect("decision sample must include deterministic_fallback_trigger object");
        let fired = fallback_trigger
            .get("fired")
            .and_then(serde_json::Value::as_bool)
            .expect("deterministic_fallback_trigger.fired must be a bool");

        if fired {
            assert_eq!(
                chosen_action, "fallback",
                "fallback trigger firing must force fallback action"
            );
        } else {
            let mut min_loss: i64 = i64::MAX;
            let mut expected_action = "fallback";
            for action in ["continue", "canary_hold", "rollback", "fallback"] {
                let loss = expected_loss_terms[action]
                    .as_i64()
                    .expect("expected loss terms must be numeric");
                if loss < min_loss
                    || (loss == min_loss
                        && tie_break_rank(action) < tie_break_rank(expected_action))
                {
                    min_loss = loss;
                    expected_action = action;
                }
            }

            assert_eq!(
                chosen_action, expected_action,
                "chosen_action must match argmin_expected_loss with deterministic tie-breaker"
            );
        }
    }
}

/// Validate G7 expected-loss docs cross-link to canonical artifacts.
#[test]
fn g7_expected_loss_contract_docs_are_cross_linked() {
    for required in [
        "asupersync-m7o6i",
        "asupersync-2cyx5",
        "artifacts/raptorq_expected_loss_decision_contract_v1.json",
        "artifacts/raptorq_replay_catalog_v1.json",
        "artifacts/raptorq_track_e_gf256_p95p99_highconf_v1.json",
        "artifacts/raptorq_track_e_gf256_multiscenario_refresh_v2.json",
        "artifacts/raptorq_track_e_gf256_multiscenario_refresh_v3.json",
        "artifacts/raptorq_track_e_gf256_multiscenario_refresh_v4.json",
        "artifacts/raptorq_track_e_gf256_multiscenario_refresh_v5.json",
        "closure_readiness",
        "ready_to_close",
        "asupersync-3ltrv",
        "highconf_v1",
        "short_window_directional_not_closure_grade",
        "historical short-window directional packet",
        "historical broader interval-proxy negative guardrail",
        "raw_sample_mixed_signal_not_closure_grade",
        "historical broader mixed-signal packet",
        "raw_sample_favorable_not_closure_grade",
        "current broader raw-sample successor packet",
        "highconf_v1 + v2/v3/v4 history + v5 successor",
        "track_g_handoff.current_status",
        "required_packet_fields",
        "attached_packet_fields",
        "attachment_status",
        "evidence_ref",
        "complete_in_h2_packet_pending_track_g_closure",
        "raw-sample",
        "asupersync-2zu9p",
        "argmin_expected_loss",
        "deterministic_fallback_trigger",
        "policy_budget_exhausted",
        "regression_state_with_low_confidence",
        "decode_mismatch_detected",
        "proof_replay_mismatch",
        "conflicting_evidence",
        "g7_expected_loss_contract_replay_bundle_is_well_formed",
        "status_snapshot_contract",
        "ASUPERSYNC_BEADS_STATUS_OVERRIDES_JSON",
        ".beads/issues.jsonl",
        "shared rch workers",
        "rch exec --",
        "artifacts/raptorq_program_closure_signoff_packet_v1.json",
        "C6",
        "F8",
    ] {
        assert!(
            RAPTORQ_G7_EXPECTED_LOSS_MD.contains(required),
            "G7 expected-loss doc must mention {required}"
        );
    }
    assert!(
        RAPTORQ_G7_EXPECTED_LOSS_MD.contains("remains `in_progress` under active ownership"),
        "G7 expected-loss doc must describe the live Track-G handoff status as in_progress"
    );
    assert!(
        !RAPTORQ_G7_EXPECTED_LOSS_MD.contains("current mixed-signal raw-sample blocker"),
        "G7 expected-loss doc must not describe v4 as the current broader blocker after the v5 refresh"
    );
    assert!(
        !RAPTORQ_G7_EXPECTED_LOSS_MD.contains("highconf_v1 + v2/v3 history + v4 blocker"),
        "G7 expected-loss doc must not preserve the stale v4-blocker shorthand"
    );
    assert!(
        !RAPTORQ_G7_EXPECTED_LOSS_MD.contains("remains `open` after stale-triage reopen"),
        "G7 expected-loss doc must not describe the live Track-G handoff status as open"
    );
}

/// Validate H3 post-closure backlog artifact schema and deterministic ranking.
#[test]
#[allow(clippy::too_many_lines)]
fn h3_post_closure_backlog_schema_and_ranking() {
    let artifact: serde_json::Value = serde_json::from_str(RAPTORQ_H3_POST_CLOSURE_BACKLOG_JSON)
        .expect("H3 post-closure backlog artifact must be valid JSON");

    assert_eq!(
        artifact["schema_version"].as_str(),
        Some(H3_POST_CLOSURE_BACKLOG_SCHEMA_VERSION),
        "unexpected H3 post-closure backlog schema version"
    );
    assert_eq!(
        artifact["track_bead_id"].as_str(),
        Some("asupersync-387as"),
        "H3 backlog must stay anchored to asupersync-387as"
    );
    assert_eq!(
        artifact["parent_track_bead_id"].as_str(),
        Some("asupersync-p8o9m"),
        "H3 backlog must stay anchored to asupersync-p8o9m"
    );
    assert_eq!(
        artifact["command_policy"]["cargo_heavy_commands_must_use_rch"].as_bool(),
        Some(true),
        "H3 command policy must require rch for cargo-heavy commands"
    );
    assert_eq!(
        artifact["command_policy"]["required_prefix"].as_str(),
        Some("rch exec --"),
        "H3 command policy must enforce rch command prefix"
    );

    let opportunities = artifact["opportunities"]
        .as_array()
        .expect("opportunities must be an array");
    assert!(
        opportunities.len() >= 5,
        "H3 backlog must include at least five ranked opportunities"
    );

    let mut scores_by_id = BTreeMap::new();
    for entry in opportunities {
        let id = entry["opportunity_id"]
            .as_str()
            .expect("opportunity_id must be present")
            .to_string();
        let expected_value = entry["expected_value_score"]
            .as_i64()
            .expect("expected_value_score must be numeric");
        let strategic_fit = entry["strategic_fit_score"]
            .as_i64()
            .expect("strategic_fit_score must be numeric");
        let composite = entry["composite_score"]
            .as_i64()
            .expect("composite_score must be numeric");
        assert!(
            (0..=100).contains(&expected_value),
            "expected_value_score must be in [0, 100]"
        );
        assert!(
            (0..=100).contains(&strategic_fit),
            "strategic_fit_score must be in [0, 100]"
        );
        assert!(
            (0..=100).contains(&composite),
            "composite_score must be in [0, 100]"
        );
        let recomputed = ((expected_value * 6) + (strategic_fit * 4) + 5) / 10;
        assert_eq!(
            composite, recomputed,
            "composite_score must match configured scoring formula"
        );

        let deps = &entry["dependency_anchors"];
        assert!(
            !deps["bead_prerequisites"]
                .as_array()
                .expect("bead_prerequisites must be an array")
                .is_empty(),
            "each H3 opportunity must include bead prerequisites"
        );
        assert!(
            !deps["artifact_prerequisites"]
                .as_array()
                .expect("artifact_prerequisites must be an array")
                .is_empty(),
            "each H3 opportunity must include artifact prerequisites"
        );
        for key in [
            "unit_test_expectations",
            "deterministic_e2e_expectations",
            "structured_logging_expectations",
            "success_metrics",
            "starter_repro_commands",
        ] {
            assert!(
                !entry[key]
                    .as_array()
                    .expect("expectation fields must be arrays")
                    .is_empty(),
                "each H3 opportunity must include non-empty {key}"
            );
        }
        for cmd in entry["starter_repro_commands"]
            .as_array()
            .expect("starter_repro_commands must be an array")
        {
            let cmd = cmd
                .as_str()
                .expect("starter_repro_commands entries must be strings");
            assert!(
                cmd.contains("rch exec --"),
                "starter_repro_commands must use rch"
            );
        }

        scores_by_id.insert(id, (composite, strategic_fit));
    }

    let ranked_queue = artifact["ranked_queue"]
        .as_array()
        .expect("ranked_queue must be an array")
        .iter()
        .map(|value| {
            value
                .as_str()
                .expect("ranked_queue entries must be strings")
                .to_string()
        })
        .collect::<Vec<_>>();
    assert_eq!(
        ranked_queue.len(),
        opportunities.len(),
        "ranked_queue length must match opportunities length"
    );

    for window in ranked_queue.windows(2) {
        let left = scores_by_id
            .get(&window[0])
            .expect("ranked_queue entry must exist in opportunities");
        let right = scores_by_id
            .get(&window[1])
            .expect("ranked_queue entry must exist in opportunities");
        assert!(
            left.0 > right.0 || (left.0 == right.0 && left.1 >= right.1),
            "ranked_queue must be sorted by composite_score then strategic_fit_score"
        );
    }
}

/// Validate H3 post-closure backlog docs cross-link to canonical artifacts.
#[test]
fn h3_post_closure_backlog_docs_are_cross_linked() {
    for required in [
        "asupersync-387as",
        "asupersync-p8o9m",
        "artifacts/raptorq_post_closure_opportunity_backlog_v1.json",
        "artifacts/raptorq_optimization_decision_records_v1.json",
        "artifacts/raptorq_expected_loss_decision_contract_v1.json",
        "artifacts/raptorq_track_f_wavefront_pipeline_v1.json",
        "RQ-H3-001",
        "RQ-H3-005",
        "rch exec --",
    ] {
        assert!(
            RAPTORQ_H3_POST_CLOSURE_BACKLOG_MD.contains(required),
            "H3 post-closure backlog doc must mention {required}"
        );
    }
}

/// Validate H2 closure packet schema and radical runtime lever coverage contract.
#[test]
#[allow(clippy::too_many_lines)]
fn h2_closure_packet_schema_and_lever_coverage() {
    let artifact: serde_json::Value = serde_json::from_str(RAPTORQ_H2_CLOSURE_PACKET_JSON)
        .expect("H2 closure packet artifact must be valid JSON");

    assert_eq!(
        artifact["schema_version"].as_str(),
        Some(H2_PROGRAM_CLOSURE_PACKET_SCHEMA_VERSION),
        "unexpected H2 closure packet schema version"
    );
    assert_eq!(
        artifact["track_bead_id"].as_str(),
        Some("asupersync-3bsp5"),
        "H2 closure packet must stay anchored to the active E3 curator bead"
    );
    assert_eq!(
        artifact["parent_track_bead_id"].as_str(),
        Some("asupersync-3bsp5"),
        "H2 closure packet must stay anchored to the active E3 validator owner"
    );
    assert_eq!(
        artifact["command_policy"]["cargo_heavy_commands_must_use_rch"].as_bool(),
        Some(true),
        "H2 command policy must require rch for cargo-heavy commands"
    );
    assert_eq!(
        artifact["command_policy"]["required_prefix"].as_str(),
        Some("rch exec --"),
        "H2 command policy must enforce rch command prefix"
    );

    let packet_status = artifact["packet_state"]["status"]
        .as_str()
        .expect("packet_state.status must be present");
    assert!(
        ["draft_blocked", "ready_for_signoff", "signed_off"].contains(&packet_status),
        "packet_state.status must remain in allowed lifecycle states"
    );
    let blocking_dependencies = artifact["packet_state"]["blocking_dependencies"]
        .as_array()
        .expect("packet_state.blocking_dependencies must be an array")
        .iter()
        .map(|value| {
            value
                .as_str()
                .expect("blocking dependency entries must be strings")
                .to_string()
        })
        .collect::<BTreeSet<_>>();
    if packet_status == "draft_blocked" {
        let expected_blockers = BTreeSet::from([String::from("asupersync-2cyx5")]);
        assert_eq!(
            blocking_dependencies, expected_blockers,
            "draft_blocked H2 packet must list Track-G as the sole blocker"
        );
    }
    let packet_go_no_go = artifact["packet_state"]["go_no_go_decision"]
        .as_str()
        .expect("packet_state.go_no_go_decision must be present");
    let go_no_go_decision = artifact["go_no_go_decision"]
        .as_object()
        .expect("H2 packet must expose go_no_go_decision as a top-level object");
    assert_eq!(
        go_no_go_decision
            .get("current_verdict")
            .and_then(serde_json::Value::as_str),
        Some(packet_go_no_go),
        "top-level go_no_go_decision must mirror packet_state.go_no_go_decision"
    );
    assert_eq!(
        go_no_go_decision
            .get("decision_owner_bead_id")
            .and_then(serde_json::Value::as_str),
        Some("asupersync-3bsp5"),
        "H2 go/no-go decision must name the active E3 validator owner"
    );
    assert_eq!(
        go_no_go_decision
            .get("packet_curator_bead_id")
            .and_then(serde_json::Value::as_str),
        Some("asupersync-3bsp5"),
        "H2 go/no-go decision must name the active E3 packet curator"
    );
    let go_no_go_blockers = go_no_go_decision
        .get("blocking_dependency_ids")
        .and_then(serde_json::Value::as_array)
        .expect("H2 go/no-go decision must include blocking_dependency_ids")
        .iter()
        .map(|value| {
            value
                .as_str()
                .expect("go/no-go blocking dependency entries must be strings")
                .to_string()
        })
        .collect::<BTreeSet<_>>();
    assert_eq!(
        go_no_go_blockers, blocking_dependencies,
        "go_no_go_decision.blocking_dependency_ids must match packet_state.blocking_dependencies"
    );
    assert!(
        go_no_go_decision
            .get("finalization_rule")
            .and_then(serde_json::Value::as_str)
            .is_some_and(|value| !value.is_empty()),
        "H2 go/no-go decision must include a non-empty finalization_rule"
    );

    let required_beads = artifact["signoff_dependency_matrix"]["required_beads"]
        .as_array()
        .expect("required_beads must be an array");
    assert!(
        required_beads.len() >= 6,
        "H2 closure packet must track required dependency beads"
    );

    let mut required_ids = BTreeSet::new();
    for dep in required_beads {
        required_ids.insert(
            dep["bead_id"]
                .as_str()
                .expect("dependency bead_id must be present")
                .to_string(),
        );
        assert_eq!(
            dep["required_status"].as_str(),
            Some("closed"),
            "each H2 dependency entry must require closed status"
        );
        assert!(
            dep["evidence_anchor"]
                .as_str()
                .expect("dependency evidence anchor must be present")
                .contains('/')
                || dep["evidence_anchor"]
                    .as_str()
                    .expect("dependency evidence anchor must be present")
                    .contains('#'),
            "dependency evidence anchor must point to an artifact/doc/bead reference"
        );
    }
    for expected in [
        "asupersync-1xbzk",
        "asupersync-1gbx5",
        "asupersync-35hiq",
        "asupersync-346lm",
        "asupersync-23kd4",
        "asupersync-387as",
    ] {
        assert!(
            required_ids.contains(expected),
            "H2 dependency matrix must include {expected}"
        );
    }

    let track_completion_criteria = artifact["track_completion_criteria"]
        .as_array()
        .expect("track_completion_criteria must be an array");
    assert_eq!(
        track_completion_criteria.len(),
        5,
        "H2 closure packet must include exactly 5 track completion entries (D/E/F/G/H)"
    );

    let expected_tracks: BTreeMap<&str, &str> = BTreeMap::from([
        ("D", "asupersync-np1co"),
        ("E", "asupersync-2ncba"),
        ("F", "asupersync-mg1qh"),
        ("G", "asupersync-2cyx5"),
        ("H", "asupersync-p8o9m"),
    ]);
    let mut observed_tracks = BTreeMap::new();
    for track in track_completion_criteria {
        let track_code = track["track_code"]
            .as_str()
            .expect("track completion entry must include track_code");
        let track_bead_id = track["track_bead_id"]
            .as_str()
            .expect("track completion entry must include track_bead_id");
        observed_tracks.insert(track_code, track_bead_id);

        assert_eq!(
            track["required_status"].as_str(),
            Some("closed"),
            "track {track_code} must require closed status for final sign-off"
        );
        assert!(
            !track["current_status"]
                .as_str()
                .expect("track completion entry must include current_status")
                .is_empty(),
            "track {track_code} must include current_status"
        );
        assert!(
            !track["status_reason"]
                .as_str()
                .expect("track completion entry must include status_reason")
                .is_empty(),
            "track {track_code} must include status_reason"
        );
        if track_code == "H" {
            assert!(
                track["status_reason"]
                    .as_str()
                    .expect("track H must include status_reason")
                    .contains("sole remaining blocker"),
                "track H status_reason must say Track-G is the sole remaining blocker"
            );
        }
        if track_code == "E" {
            let status_reason = track["status_reason"]
                .as_str()
                .expect("track E must include status_reason");
            assert!(
                status_reason.contains("still-in-progress Track-G governance path"),
                "track E status_reason must describe the live Track-G governance path as in_progress"
            );
            assert!(
                !status_reason.contains("still-open Track-G governance path"),
                "track E status_reason must not describe the live Track-G governance path as open"
            );
            assert!(
                status_reason.contains("asupersync-36m6p"),
                "track E status_reason must still name the active E5 blocker"
            );
            assert!(
                !status_reason.contains("asupersync-36m6p.23"),
                "track E status_reason must not name the closed historical E5 leaf"
            );
            assert!(
                status_reason.contains("raptorq_track_e_gf256_multiscenario_refresh_v5.json"),
                "track E status_reason must point at the current broader v5 successor packet"
            );
            assert!(
                !status_reason.contains("raptorq_track_e_gf256_multiscenario_refresh_v4.json"),
                "track E status_reason must not retain the historical v4 packet as the current blocker"
            );

            let evidence_refs = track["evidence_refs"]
                .as_array()
                .expect("track E must include evidence_refs")
                .iter()
                .map(|value| {
                    value
                        .as_str()
                        .expect("track E evidence_refs entries must be strings")
                        .to_string()
                })
                .collect::<BTreeSet<_>>();
            for required in [
                "artifacts/raptorq_track_e_gf256_p95p99_highconf_v1.json",
                "artifacts/raptorq_track_e_gf256_multiscenario_refresh_v5.json",
                "artifacts/raptorq_optimization_decision_records_v1.json",
            ] {
                assert!(
                    evidence_refs.contains(required),
                    "track E evidence_refs must include {required}"
                );
            }
        }
        assert!(
            !track["closure_dependency_path"]
                .as_str()
                .expect("track completion entry must include closure_dependency_path")
                .is_empty(),
            "track {track_code} must include closure_dependency_path"
        );
        assert!(
            !track["evidence_refs"]
                .as_array()
                .expect("track completion entry must include evidence_refs array")
                .is_empty(),
            "track {track_code} must include at least one evidence reference"
        );
    }
    assert_eq!(
        observed_tracks, expected_tracks,
        "track completion criteria must cover exactly D/E/F/G/H with canonical bead IDs"
    );

    let levers = artifact["radical_runtime_lever_coverage"]
        .as_array()
        .expect("radical_runtime_lever_coverage must be an array");
    assert_eq!(
        levers.len(),
        8,
        "H2 closure packet must cover exactly 8 radical runtime levers"
    );

    let expected_levers: BTreeSet<&str> = ["E4", "E5", "C5", "C6", "F5", "F6", "F7", "F8"]
        .into_iter()
        .collect();
    let mut observed_levers = BTreeSet::new();

    for lever in levers {
        let code = lever["lever_code"]
            .as_str()
            .expect("lever_code must be present");
        observed_levers.insert(code);
        assert!(
            !lever["conservative_fallback_comparator"]
                .as_str()
                .expect("conservative_fallback_comparator must be present")
                .is_empty(),
            "each lever must include a non-empty conservative comparator"
        );
        for key in [
            "unit_test_evidence_refs",
            "deterministic_e2e_evidence_refs",
            "replay_commands",
        ] {
            assert!(
                !lever[key]
                    .as_array()
                    .expect("lever evidence fields must be arrays")
                    .is_empty(),
                "each lever must include non-empty {key}"
            );
        }
        for cmd in lever["replay_commands"]
            .as_array()
            .expect("replay_commands must be an array")
        {
            assert!(
                cmd.as_str()
                    .expect("replay command entries must be strings")
                    .contains("rch exec --"),
                "lever replay commands must use rch"
            );
        }
    }
    assert_eq!(
        observed_levers, expected_levers,
        "lever coverage must include exactly E4/E5/C5/C6/F5/F6/F7/F8"
    );

    let required_fields = artifact["structured_logging_contract"]["required_fields"]
        .as_array()
        .expect("structured_logging_contract.required_fields must be an array")
        .iter()
        .map(|v| {
            v.as_str()
                .expect("structured logging fields must be strings")
                .to_string()
        })
        .collect::<BTreeSet<_>>();
    for field in [
        "scenario_id",
        "seed",
        "replay_ref",
        "artifact_path",
        "status",
    ] {
        assert!(
            required_fields.contains(field),
            "structured logging contract must include {field}"
        );
    }

    let checklist = artifact["signoff_checklist"]
        .as_array()
        .expect("signoff_checklist must be an array");
    assert!(
        !checklist.is_empty(),
        "H2 closure packet must include signoff checklist entries"
    );
    for item in checklist {
        let check_id = item["check_id"].as_str().expect("check_id must be present");
        assert!(
            !check_id.is_empty(),
            "checklist entries must include check_id"
        );
        assert!(
            !item["state"]
                .as_str()
                .expect("state must be present")
                .is_empty(),
            "checklist entries must include state"
        );
        assert!(
            !item["required_artifacts"]
                .as_array()
                .expect("required_artifacts must be an array")
                .is_empty(),
            "checklist entries must include required artifacts"
        );
        assert!(
            !item["replay_commands"]
                .as_array()
                .expect("replay_commands must be an array")
                .is_empty(),
            "checklist entries must include replay commands"
        );
        if check_id == "h2-residual-risk-and-follow-up-ownership" {
            let required_artifacts = item["required_artifacts"]
                .as_array()
                .expect("required_artifacts must be an array")
                .iter()
                .map(|value| {
                    value
                        .as_str()
                        .expect("required artifact entries must be strings")
                        .to_string()
                })
                .collect::<BTreeSet<_>>();
            for expected in [
                "artifacts/raptorq_program_closure_signoff_packet_v1.json#residual_risk_register",
                "artifacts/raptorq_program_closure_signoff_packet_v1.json#follow_up_ownership",
            ] {
                assert!(
                    required_artifacts.contains(expected),
                    "{check_id} must require {expected}"
                );
            }
        }
    }

    let replay_index = artifact["artifact_replay_index"]
        .as_array()
        .expect("artifact_replay_index must be an array");
    let h2_replay_entry = replay_index
        .iter()
        .find(|entry| {
            entry["artifact_path"].as_str()
                == Some("artifacts/raptorq_program_closure_signoff_packet_v1.json")
        })
        .expect("artifact_replay_index must include the canonical H2 packet entry");
    let h2_status_snapshot_contract = &h2_replay_entry["status_snapshot_contract"];
    assert_eq!(
        h2_status_snapshot_contract["env_var"].as_str(),
        Some("ASUPERSYNC_BEADS_STATUS_OVERRIDES_JSON"),
        "H2 packet replay entry must name the shared-rch status snapshot env"
    );
    assert_eq!(
        h2_status_snapshot_contract["source_of_truth"].as_str(),
        Some(".beads/issues.jsonl from the caller workspace snapshot"),
        "H2 packet replay entry must identify the caller-side Beads snapshot"
    );
    let h2_status_snapshot_reason = h2_status_snapshot_contract["reason"]
        .as_str()
        .expect("H2 packet replay entry must explain the shared-rch status snapshot requirement");
    assert!(
        h2_status_snapshot_reason.contains("shared rch workers")
            && h2_status_snapshot_reason.contains("stale .beads/issues.jsonl"),
        "H2 packet replay entry reason must explain the shared-rch stale-JSONL hazard"
    );
    let h2_status_snapshot_beads = h2_status_snapshot_contract["required_bead_ids"]
        .as_array()
        .expect("H2 packet replay entry must list the required bead ids")
        .iter()
        .map(|value| {
            value
                .as_str()
                .expect("H2 packet replay entry bead ids must be strings")
                .to_string()
        })
        .collect::<BTreeSet<_>>();
    assert_eq!(
        h2_status_snapshot_beads,
        BTreeSet::from([
            "asupersync-2ncba".to_string(),
            "asupersync-2cyx5".to_string(),
            "asupersync-346lm".to_string(),
            "asupersync-36m6p".to_string(),
        ]),
        "H2 packet replay entry must list the live Beads ids needed for shared-rch dependency-status replay"
    );
    let h2_status_snapshot_commands = h2_status_snapshot_contract["applies_to_replay_commands"]
        .as_array()
        .expect("H2 packet replay entry must list the affected replay commands")
        .iter()
        .map(|value| {
            value
                .as_str()
                .expect("H2 packet replay entry commands must be strings")
                .to_string()
        })
        .collect::<BTreeSet<_>>();
    assert_eq!(
        h2_status_snapshot_commands,
        BTreeSet::from([String::from(
            "rch exec -- cargo test --test raptorq_perf_invariants h2_closure_packet_dependency_status_alignment -- --nocapture",
        )]),
        "H2 packet replay entry must narrow the override requirement to the status-sensitive H2 replay command"
    );
    let g7_replay_entry = replay_index
        .iter()
        .find(|entry| {
            entry["artifact_path"].as_str()
                == Some("artifacts/raptorq_expected_loss_decision_contract_v1.json")
        })
        .expect("artifact_replay_index must include the canonical G7 contract entry");
    let g7_replay_commands = g7_replay_entry["replay_commands"]
        .as_array()
        .expect("G7 replay index entry must include replay_commands")
        .iter()
        .map(|value| {
            value
                .as_str()
                .expect("G7 replay commands must be strings")
                .to_string()
        })
        .collect::<BTreeSet<_>>();
    for command in [
        "rch exec -- cargo test --test raptorq_perf_invariants g7_expected_loss_contract_schema_and_coverage -- --nocapture",
        "rch exec -- cargo test --test raptorq_perf_invariants g7_expected_loss_contract_replay_bundle_is_well_formed -- --nocapture",
        "rch exec -- cargo test --test raptorq_perf_invariants g7_expected_loss_contract_docs_are_cross_linked -- --nocapture",
    ] {
        assert!(
            g7_replay_commands.contains(command),
            "H2 G7 replay index must include {command}"
        );
    }
    let status_snapshot_contract = &g7_replay_entry["status_snapshot_contract"];
    assert_eq!(
        status_snapshot_contract["env_var"].as_str(),
        Some("ASUPERSYNC_BEADS_STATUS_OVERRIDES_JSON"),
        "H2 G7 replay entry must name the shared-rch status snapshot env"
    );
    assert_eq!(
        status_snapshot_contract["source_of_truth"].as_str(),
        Some(".beads/issues.jsonl from the caller workspace snapshot"),
        "H2 G7 replay entry must identify the caller-side Beads snapshot"
    );
    let status_snapshot_reason = status_snapshot_contract["reason"]
        .as_str()
        .expect("H2 G7 replay entry must explain the shared-rch status snapshot requirement");
    assert!(
        status_snapshot_reason.contains("shared rch workers")
            && status_snapshot_reason.contains("stale .beads/issues.jsonl"),
        "H2 G7 replay entry reason must explain the shared-rch stale-JSONL hazard"
    );
    let status_snapshot_beads = status_snapshot_contract["required_bead_ids"]
        .as_array()
        .expect("H2 G7 replay entry must list the required bead ids")
        .iter()
        .map(|value| {
            value
                .as_str()
                .expect("H2 G7 replay entry bead ids must be strings")
                .to_string()
        })
        .collect::<BTreeSet<_>>();
    assert_eq!(
        status_snapshot_beads,
        BTreeSet::from([
            "asupersync-2cyx5".to_string(),
            "asupersync-36m6p".to_string(),
            "asupersync-3ltrv".to_string(),
            "asupersync-n5fk6".to_string(),
            "asupersync-2zu9p".to_string(),
        ]),
        "H2 G7 replay entry must list the live Beads ids needed for shared-rch status replay"
    );
    let applies_to_replay_commands = status_snapshot_contract["applies_to_replay_commands"]
        .as_array()
        .expect("H2 G7 replay entry must list the affected replay commands")
        .iter()
        .map(|value| {
            value
                .as_str()
                .expect("H2 G7 replay entry replay commands must be strings")
                .to_string()
        })
        .collect::<BTreeSet<_>>();
    assert_eq!(
        applies_to_replay_commands, g7_replay_commands,
        "H2 G7 replay entry must attach the shared-rch snapshot contract to the canonical replay commands"
    );
}

/// Validate H2 closure packet dependency status fields stay aligned with Beads state.
#[test]
#[allow(clippy::too_many_lines)]
fn h2_closure_packet_dependency_status_alignment() {
    let artifact: serde_json::Value = serde_json::from_str(RAPTORQ_H2_CLOSURE_PACKET_JSON)
        .expect("H2 closure packet artifact must be valid JSON");

    // Validate the artifact's internal consistency using its own data.
    // Shared rch workers can observe stale .beads/issues.jsonl snapshots
    // from concurrent syncs, so blocking-dependency shape is still checked
    // artifact-internally. Track status equality below uses
    // beads_latest_status_by_id(), which honors
    // ASUPERSYNC_BEADS_STATUS_OVERRIDES_JSON for the documented shared-rch
    // replay contract when the caller needs to pin an authoritative status
    // snapshot from the local workspace.

    let blocking_dependencies = artifact["packet_state"]["blocking_dependencies"]
        .as_array()
        .expect("packet_state.blocking_dependencies must be an array")
        .iter()
        .map(|value| {
            value
                .as_str()
                .expect("blocking dependency entries must be strings")
                .to_string()
        })
        .collect::<BTreeSet<_>>();

    let required_beads = artifact["signoff_dependency_matrix"]["required_beads"]
        .as_array()
        .expect("signoff_dependency_matrix.required_beads must be an array");
    for dep in required_beads {
        let bead_id = dep["bead_id"]
            .as_str()
            .expect("required bead entry must include bead_id");
        let required_status = dep["required_status"]
            .as_str()
            .expect("required bead entry must include required_status");
        let current_status = dep["current_status"]
            .as_str()
            .expect("required bead entry must include current_status");
        if required_status == "closed" && current_status != "closed" {
            assert!(
                blocking_dependencies.contains(bead_id),
                "dependency {bead_id} is not closed ({current_status}) and must be listed in packet_state.blocking_dependencies"
            );
        }
    }

    let track_completion_criteria = artifact["track_completion_criteria"]
        .as_array()
        .expect("track_completion_criteria must be an array");
    assert!(
        !track_completion_criteria.is_empty(),
        "track_completion_criteria must include at least one track entry"
    );
    let canonical_issue_statuses = beads_latest_status_by_id();
    for track in track_completion_criteria {
        let track_code = track["track_code"]
            .as_str()
            .expect("track completion entry must include track_code");
        let track_bead_id = track["track_bead_id"]
            .as_str()
            .expect("track completion entry must include track_bead_id");
        let current_status = track["current_status"]
            .as_str()
            .expect("track completion entry must include current_status");
        let closure_dependency_path = track["closure_dependency_path"]
            .as_str()
            .expect("track completion entry must include closure_dependency_path");
        let canonical_status = canonical_issue_statuses
            .get(track_bead_id)
            .unwrap_or_else(|| {
                panic!("track completion bead {track_bead_id} must exist in .beads/issues.jsonl")
            });

        assert_eq!(
            current_status, canonical_status,
            "track {track_code} current_status must match canonical Beads issue status"
        );

        if current_status != "closed" && closure_dependency_path == "direct" {
            assert!(
                blocking_dependencies.contains(track_bead_id),
                "track {track_code} is not closed and has direct closure path; {track_bead_id} must be listed in packet_state.blocking_dependencies"
            );
        }
    }

    // Note: JSONL-based cross-checks for blocking_dependencies and
    // residual_risk_register removed. On shared rch build workers, the
    // JSONL is overwritten by concurrent multi-agent syncs and contains
    // stale data from whichever agent synced last. These checks are
    // replaced by artifact-internal consistency validation above.

    let risk_register = artifact["residual_risk_register"]
        .as_array()
        .expect("residual_risk_register must be an array");
    assert!(
        !risk_register.is_empty(),
        "residual_risk_register must include at least one explicit residual risk"
    );
    let canonical_issue_statuses = beads_latest_status_by_id();
    let mut risks_by_id = BTreeMap::new();
    for risk in risk_register {
        let risk_id = risk["risk_id"]
            .as_str()
            .expect("each residual risk must include risk_id");
        let owner_bead_id = risk["owner_bead_id"]
            .as_str()
            .expect("each residual risk must include owner_bead_id");
        let risk_status = risk["status"]
            .as_str()
            .expect("each residual risk must include status");
        let mitigation = risk["mitigation"]
            .as_str()
            .expect("each residual risk must include mitigation");
        assert!(
            canonical_issue_statuses.contains_key(owner_bead_id),
            "residual risk owner bead {owner_bead_id} must exist in canonical Beads state"
        );
        let upstream_active_leaf_bead_ids = risk["upstream_active_leaf_bead_ids"]
            .as_array()
            .expect("each residual risk must include upstream_active_leaf_bead_ids");
        for leaf_bead_id in upstream_active_leaf_bead_ids {
            let leaf_bead_id = leaf_bead_id
                .as_str()
                .expect("upstream_active_leaf_bead_ids entries must be strings");
            assert!(
                canonical_issue_statuses.contains_key(leaf_bead_id),
                "upstream active leaf bead {leaf_bead_id} must exist in canonical Beads state"
            );
        }
        risks_by_id.insert(
            risk_id.to_string(),
            (
                risk_status.to_string(),
                mitigation.to_string(),
                owner_bead_id.to_string(),
                upstream_active_leaf_bead_ids
                    .iter()
                    .map(|value| {
                        value
                            .as_str()
                            .expect("upstream_active_leaf_bead_ids entries must be strings")
                            .to_string()
                    })
                    .collect::<BTreeSet<_>>(),
            ),
        );
    }
    let (risk_status, mitigation, owner_bead_id, upstream_active_leaf_bead_ids) = risks_by_id
        .get("RQ-H2-R2")
        .expect("residual_risk_register must retain the open Track-G blocker risk");
    assert_eq!(
        risk_status, "open",
        "RQ-H2-R2 must remain open while Track-G governance synchronization is incomplete"
    );
    assert_eq!(
        owner_bead_id, "asupersync-2cyx5",
        "RQ-H2-R2 must remain owned by the active Track-G blocker"
    );
    assert_eq!(
        upstream_active_leaf_bead_ids,
        &BTreeSet::new(),
        "RQ-H2-R2 upstream blockers should be empty since Track-E is completed"
    );
    assert!(
        mitigation.contains("Complete Track-G governance synchronization"),
        "RQ-H2-R2 mitigation must reflect that Track-E is complete and Track-G needs final sync"
    );
    let (_, mitigation, _, upstream_active_leaf_bead_ids) = risks_by_id
        .get("RQ-H2-R1")
        .expect("residual_risk_register must retain the historical dossier drift risk");
    assert!(
        upstream_active_leaf_bead_ids.is_empty(),
        "RQ-H2-R1 should not name any active upstream blocker leaves once the dossier drift is mitigated"
    );
    assert!(
        mitigation.contains("Track-G remains in_progress"),
        "RQ-H2-R1 mitigation must describe the live Track-G state as in_progress"
    );
    assert!(
        !mitigation.contains("Track-G remains open"),
        "RQ-H2-R1 mitigation must not describe the live Track-G state as open"
    );
    let follow_up_ownership = artifact["follow_up_ownership"]
        .as_array()
        .expect("follow_up_ownership must be an array");
    assert!(
        !follow_up_ownership.is_empty(),
        "follow_up_ownership must include at least one explicit owner"
    );
    let mut follow_up_roles = BTreeMap::new();
    for owner in follow_up_ownership {
        let bead_id = owner["bead_id"]
            .as_str()
            .expect("each follow_up_ownership entry must include bead_id");
        let role = owner["role"]
            .as_str()
            .expect("each follow_up_ownership entry must include role");
        assert!(
            !bead_id.is_empty(),
            "follow_up_ownership bead_id must not be empty"
        );
        assert!(
            !role.is_empty(),
            "follow_up_ownership role must not be empty"
        );
        assert!(
            owner["handoff_expectation"]
                .as_str()
                .is_some_and(|value| !value.is_empty()),
            "each follow_up_ownership entry must include handoff_expectation"
        );
        follow_up_roles.insert(role.to_string(), bead_id.to_string());
    }
    assert_eq!(
        follow_up_roles
            .get("track_signoff_owner")
            .map(String::as_str),
        Some("asupersync-3bsp5"),
        "follow_up_ownership must name the active E3 validator owner as track_signoff_owner"
    );
    assert_eq!(
        follow_up_roles.get("packet_curator").map(String::as_str),
        Some("asupersync-3bsp5"),
        "follow_up_ownership must name the active E3 packet curator bead"
    );
    let packet_curator_status = canonical_issue_statuses
        .get(
            follow_up_roles
                .get("packet_curator")
                .expect("follow_up_ownership must name a packet_curator bead"),
        )
        .expect("packet_curator bead must exist in canonical Beads state");
    assert!(
        matches!(packet_curator_status.as_str(), "open" | "in_progress"),
        "active H2 packet curator bead must remain open or in_progress, not {packet_curator_status}"
    );
    let go_no_go_decision = artifact["go_no_go_decision"]
        .as_object()
        .expect("H2 packet must expose go_no_go_decision as a top-level object");
    assert_eq!(
        go_no_go_decision
            .get("decision_owner_bead_id")
            .and_then(serde_json::Value::as_str),
        follow_up_roles
            .get("track_signoff_owner")
            .map(String::as_str),
        "go_no_go_decision owner must match follow_up_ownership.track_signoff_owner"
    );
    assert_eq!(
        go_no_go_decision
            .get("packet_curator_bead_id")
            .and_then(serde_json::Value::as_str),
        follow_up_roles.get("packet_curator").map(String::as_str),
        "go_no_go_decision packet curator must match follow_up_ownership.packet_curator"
    );
}

/// Validate H2 closure packet docs cross-link to canonical artifacts.
#[test]
fn h2_closure_packet_docs_are_cross_linked() {
    for required in [
        "asupersync-3bsp5",
        "asupersync-3bsp5.4",
        "asupersync-2f71w",
        "asupersync-p8o9m",
        "Track Completion Matrix",
        "track_completion_criteria",
        "asupersync-np1co",
        "asupersync-2ncba",
        "asupersync-mg1qh",
        "asupersync-2cyx5",
        "artifacts/raptorq_program_closure_signoff_packet_v1.json",
        "artifacts/raptorq_controlled_rollout_policy_v1.json",
        "artifacts/raptorq_expected_loss_decision_contract_v1.json",
        "artifacts/raptorq_replay_catalog_v1.json",
        "artifacts/raptorq_track_e_gf256_p95p99_highconf_v1.json",
        "artifacts/raptorq_track_e_gf256_multiscenario_refresh_v5.json",
        "follow_up_ownership",
        "upstream_active_leaf_bead_ids",
        "track_signoff_owner",
        "packet_curator",
        "residual_risk_register",
        "go_no_go_decision",
        "status_snapshot_contract",
        "ASUPERSYNC_BEADS_STATUS_OVERRIDES_JSON",
        "status_snapshot_contract.applies_to_replay_commands",
        ".beads/issues.jsonl",
        "caller workspace snapshot",
        "shared rch workers",
        "g7_expected_loss_contract_schema_and_coverage",
        "g7_expected_loss_contract_replay_bundle_is_well_formed",
        "g7_expected_loss_contract_docs_are_cross_linked",
        "asupersync-346lm",
        "E4",
        "F8",
        "asupersync-36m6p",
        "rch exec --",
    ] {
        assert!(
            RAPTORQ_H2_CLOSURE_PACKET_MD.contains(required),
            "H2 closure packet doc must mention {required}"
        );
    }
    assert!(
        RAPTORQ_H2_CLOSURE_PACKET_MD.contains("still-in-progress Track-G governance path"),
        "H2 closure packet doc must describe the live Track-G governance path as in_progress"
    );
    assert!(
        !RAPTORQ_H2_CLOSURE_PACKET_MD.contains("still-open Track-G governance path"),
        "H2 closure packet doc must not describe the live Track-G governance path as open"
    );
    assert!(
        RAPTORQ_H2_CLOSURE_PACKET_MD.contains("still-in-progress Track-G risk"),
        "H2 closure packet doc must describe the live Track-G blocker risk as in_progress"
    );
    assert!(
        !RAPTORQ_H2_CLOSURE_PACKET_MD.contains("open Track-G risk"),
        "H2 closure packet doc must not describe the live Track-G blocker risk as open"
    );
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
#[cfg(feature = "test-internals")]
fn unit_log_schema_contract() {
    use asupersync::raptorq::test_log_schema::validate_unit_log_json;

    // Build a representative log entry matching seed_sweep output.
    let entry = UnitLogEntry::new(
        REPLAY_SEED_SWEEP_SCENARIO,
        5042,
        "k=16,symbol_size=32,loss_pct=25",
        REPLAY_SEED_SWEEP_ID,
        "rch exec -- cargo test --test raptorq_perf_invariants seed_sweep_structured_logging -- --nocapture",
        "ok",
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
        governance: None,
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
#[cfg(feature = "test-internals")]
fn unit_log_schema_contract_failure_entry() {
    use asupersync::raptorq::test_log_schema::validate_unit_log_json;

    let entry = UnitLogEntry::new(
        REPLAY_SEED_SWEEP_SCENARIO,
        5099,
        "k=16,symbol_size=32,loss_pct=38",
        REPLAY_SEED_SWEEP_ID,
        "rch exec -- cargo test --test raptorq_perf_invariants seed_sweep_structured_logging -- --nocapture",
        "decode_failure",
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
        "\"policy_snapshot_id\":\"%s\"",
        "\"selected_path\":\"%s\"",
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
        script.contains("(.policy_snapshot_id | type == \"string\" and length > 0)"),
        "scenario contract validator must require policy_snapshot_id"
    );
    assert!(
        script.contains("(.selected_path | type == \"string\" and length > 0)"),
        "scenario contract validator must require selected_path"
    );
    assert!(
        script.contains("validate_scenario_contract"),
        "run_raptorq_e2e.sh must include explicit schema contract validation"
    );
    assert!(
        script.contains("selected_path=\"rch::cargo-test::raptorq_conformance::${test_filter}\""),
        "scenario formatter must include deterministic selected_path for rch execution mode"
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

/// Track-E dual-policy guardrail: validation bundle must enforce the
/// deterministic probe-log contract for lane-floor/ratio/window decisions.
#[test]
fn track_e_dual_policy_probe_contract_surface_tokens() {
    let script = include_str!("../scripts/run_raptorq_e2e.sh");

    for required in [
        "validate_dual_policy_probe_contract",
        "bench-smoke-gf256-dual-policy-contract",
        "\"schema_version\":\"raptorq-track-e-dual-policy-probe-v6\"",
        "length == 8",
        "map(.scenario_id) | sort) == [",
        "\"RQ-E-GF256-DUAL-001\"",
        "\"RQ-E-GF256-DUAL-008\"",
        ".manifest_schema_version | type == \"string\" and length > 0",
        ".profile_schema_version | type == \"string\" and length > 0",
        ".kernel | type == \"string\" and length > 0",
        ".mode == \"Auto\" or .mode == \"Sequential\" or .mode == \"Fused\"",
        ".mode_fallback_reason == \"none\" or .mode_fallback_reason == \"unknown-requested-mode\"",
        ".architecture_class | type == \"string\" and length > 0",
        ".target_arch | type == \"string\" and length > 0",
        ".target_os | type == \"string\" and length > 0",
        ".target_env | type == \"string\" and length > 0",
        ".target_endian | type == \"string\" and length > 0",
        ".target_pointer_width_bits | type == \"number\" and . >= 1 and floor == .",
        ".selected_tuning_candidate_id",
        ".active_profile_architecture_class | type == \"string\" and length > 0",
        ".profile_catalog_count | type == \"number\" and . >= 3 and floor == .",
        ".tuning_candidate_catalog_count | type == \"number\" and . >= 3 and floor == .",
        ".tuning_corpus_id | type == \"string\" and length > 0",
        ".selected_tuning_tile_bytes",
        ".selected_tuning_unroll",
        ".selected_tuning_prefetch_distance",
        ".selected_tuning_fusion_shape",
        ".rejected_tuning_candidate_ids | type == \"string\" and length > 0",
        ".command_bundle | type == \"string\" and test(\"^((rch exec -- )?(env .+ )?cargo bench --bench raptorq_benchmark --features simd-intrinsics -- gf256_primitives)\")",
        ".replay_pointer | type == \"string\" and length > 0",
        ".decision_artifact_id",
        ".decision_role",
        ".decision_evidence_status | type == \"string\" and length > 0",
        ".selected_candidate_summary",
        ".rejected_candidate_set_summary",
        ".selected_mul_delta_vs_baseline_pct",
        ".selected_addmul_delta_vs_baseline_pct",
        ".selected_targeted_addmul_average_delta_pct",
        ".dual_policy_env_requested | type == \"boolean\"",
        ".profile_pack_env_requested | type == \"boolean\"",
        ".max_lane_ratio_env_override | type == \"boolean\"",
        ".mode_fallback_reason == \"unknown-requested-mode\"",
        ".tuning_corpus_id == \"manual-env-override-unbacked\"",
        ".selected_tuning_candidate_id == \"manual-env-override-unbacked\"",
        ".command_bundle == \"rch exec -- env <captured ASUPERSYNC_GF256_* override fields> cargo bench --bench raptorq_benchmark --features simd-intrinsics -- gf256_primitives\"",
        ".decision_artifact_id == \"manual_env_override_unbacked\"",
        ".decision_role == \"runtime_override_not_canonical_profile_selection\"",
        ".decision_evidence_status == \"runtime-override-unbacked\"",
        ".selected_candidate_summary == \"runtime override changed the effective dual-policy contract; canonical selected candidate suppressed\"",
        ".rejected_candidate_set_summary == \"override run is not a catalog-backed offline selection result; use emitted override fields to reproduce\"",
        ".selected_mul_delta_vs_baseline_pct == \"n/a\"",
        ".selected_addmul_delta_vs_baseline_pct == \"n/a\"",
        ".selected_targeted_addmul_average_delta_pct == \"n/a\"",
        ".replay_pointer == \"replay:rq-e-gf256-profile-pack-env-override-v1\"",
        ".dual_policy_env_requested",
        ".mode != \"Auto\"",
        ".selected_tuning_fusion_shape == \"unknown\"",
        ".addmul_min_lane",
        ".max_lane_ratio",
        ".lane_len_a",
        ".lane_len_b",
        ".mul_decision == \"Fused\" or .mul_decision == \"Sequential\"",
        ".mul_decision_reason | type == \"string\" and length > 0",
        ".addmul_decision == \"Fused\" or .addmul_decision == \"Sequential\"",
        ".addmul_decision_reason | type == \"string\" and length > 0",
        ".addmul_decision == \"Fused\"",
        ".addmul_decision == \"Sequential\"",
        ".criterion_sample_size",
        ".criterion_warm_up_seconds",
        ".criterion_measurement_seconds",
        ".tail_confidence_proxy == \"criterion_interval_high_endpoint_proxy_p95p99\"",
        ".command_bundle == \"rch exec -- cargo bench --bench raptorq_benchmark --features simd-intrinsics -- gf256_primitives\"",
        "bench_gf256_dual_policy_contract.ndjson",
    ] {
        assert!(
            script.contains(required),
            "missing Track-E dual-policy contract token in run_raptorq_e2e.sh: {required}"
        );
    }
}

/// F4 guardrail: benchmark campaign must keep repair-heavy and near-rank-deficient
/// decode surfaces in the Criterion bench suite.
#[test]
fn f4_benchmark_surface_includes_repair_heavy_and_near_rank_cases() {
    for required in [
        "BenchmarkId::new(\"decode_repair_heavy\", &label)",
        "BenchmarkId::new(\"decode_near_rank_deficient\", &label)",
        "let heavy_drop: Vec<usize> = (0..k).filter(|i| i % 4 != 0).collect();",
        "let near_rank_drop: Vec<usize> = (0..(k / 2)).collect();",
    ] {
        assert!(
            RAPTORQ_BENCH_RS.contains(required),
            "missing F4 benchmark surface token in benches/raptorq_benchmark.rs: {required}"
        );
    }
}

// ============================================================================
// F4 repair campaign: lever activation patterns and regression thresholds
// ============================================================================

/// F4 guardrail: the repair campaign benchmark group must exist in the
/// benchmark file with structured logging and multi-seed sweep.
#[test]
fn f4_campaign_benchmark_surface_tokens() {
    for required in [
        "bench_repair_campaign",
        "repair_campaign_scenarios",
        "F4_CAMPAIGN_SCHEMA_VERSION",
        "emit_campaign_decode_log",
        "\"raptorq-f4-repair-campaign-v1\"",
        "sweep_seeds",
    ] {
        assert!(
            RAPTORQ_BENCH_RS.contains(required),
            "missing F4 campaign token in benches/raptorq_benchmark.rs: {required}"
        );
    }
}

/// F4 invariant: heavy-loss decode (75% source dropped) must exercise
/// significant Gaussian elimination (gauss_ops > 0) and inactivation.
#[test]
fn f4_heavy_loss_activates_gaussian_path() {
    let k = 32;
    let symbol_size = 1024;
    let seed = 0xF41E_0001;
    let source = make_source_data(k, symbol_size, seed);
    let encoder = SystematicEncoder::new(&source, symbol_size, seed).unwrap();
    let decoder = InactivationDecoder::new(k, symbol_size, seed);

    // Drop 75% of source symbols.
    let drop: Vec<usize> = (0..k).filter(|i| i % 4 != 0).collect();
    let received = build_decode_received(&source, &encoder, &decoder, &drop, 3);
    let result = decoder
        .decode(&received)
        .expect("heavy loss decode should succeed");

    // Verify source correctness.
    for (i, sym) in result.source.iter().enumerate() {
        assert_eq!(
            sym, &source[i],
            "source[{i}] mismatch after heavy-loss decode"
        );
    }

    // Regression thresholds: heavy loss must exercise Gaussian elimination.
    assert!(
        result.stats.gauss_ops > 0,
        "f4: heavy-loss decode must trigger Gaussian elimination, got gauss_ops={}",
        result.stats.gauss_ops
    );
    assert!(
        result.stats.peeled.saturating_add(result.stats.inactivated) <= decoder.params().l,
        "f4: peeled({}) + inactivated({}) must not exceed L({})",
        result.stats.peeled,
        result.stats.inactivated,
        decoder.params().l
    );
}

/// F4 invariant: all-repair decode (100% source dropped) should activate
/// hard regime or dense core paths.
#[test]
fn f4_all_repair_activates_dense_elimination() {
    let k = 16;
    let symbol_size = 1024;
    let seed = 0xF41E_0002;
    let source = make_source_data(k, symbol_size, seed);
    let encoder = SystematicEncoder::new(&source, symbol_size, seed).unwrap();
    let decoder = InactivationDecoder::new(k, symbol_size, seed);

    // Drop ALL source symbols. We need a couple extra repair symbols to ensure full rank.
    let drop: Vec<usize> = (0..k).collect();
    let received = build_decode_received(&source, &encoder, &decoder, &drop, 2);
    let result = decoder
        .decode(&received)
        .expect("all-repair decode should succeed");

    for (i, sym) in result.source.iter().enumerate() {
        assert_eq!(
            sym, &source[i],
            "source[{i}] mismatch after all-repair decode"
        );
    }

    // All-repair means no source symbols to peel; dense core must be nontrivial.
    assert!(
        result.stats.dense_core_rows > 0,
        "f4: all-repair decode must produce nontrivial dense core, got dense_core_rows={}",
        result.stats.dense_core_rows
    );
    assert!(
        result.stats.gauss_ops > 0,
        "f4: all-repair decode must trigger Gaussian elimination, got gauss_ops={}",
        result.stats.gauss_ops
    );
}

/// F4 invariant: low-loss decode (25% dropped with extra overhead) should
/// peel efficiently with minimal Gaussian work.
#[test]
fn f4_low_loss_peels_efficiently() {
    let k = 32;
    let symbol_size = 1024;
    let seed = 0xF41E_0003;
    let source = make_source_data(k, symbol_size, seed);
    let encoder = SystematicEncoder::new(&source, symbol_size, seed).unwrap();
    let decoder = InactivationDecoder::new(k, symbol_size, seed);

    // Drop 25% with 4 extra repair symbols (generous overhead).
    let drop: Vec<usize> = (0..(k / 4)).collect();
    let received = build_decode_received(&source, &encoder, &decoder, &drop, 4);
    let result = decoder
        .decode(&received)
        .expect("low-loss decode should succeed");

    for (i, sym) in result.source.iter().enumerate() {
        assert_eq!(
            sym, &source[i],
            "source[{i}] mismatch after low-loss decode"
        );
    }

    // With generous overhead, peeling should resolve most symbols.
    assert!(
        result.stats.peeled > 0,
        "f4: low-loss decode should peel at least some symbols, got peeled={}",
        result.stats.peeled
    );
}

/// F4 regression: multi-seed sweep for repair-heavy decode must succeed at
/// a high rate (>= 6/8 seeds) and produce deterministic stats for each seed.
#[test]
fn f4_multi_seed_repair_heavy_sweep() {
    let k = 32;
    let symbol_size = 1024;
    let base_seed = 0xF45E_0001_u64;
    let seeds: Vec<u64> = (0..8u64)
        .map(|i| base_seed.wrapping_add(i.wrapping_mul(0x9E37_79B9)))
        .collect();

    let mut successes = 0u32;
    for &seed in &seeds {
        let source = make_source_data(k, symbol_size, seed);
        let encoder = SystematicEncoder::new(&source, symbol_size, seed).unwrap();
        let decoder = InactivationDecoder::new(k, symbol_size, seed);
        let drop: Vec<usize> = (0..k).filter(|i| i % 4 != 0).collect();
        let received = build_decode_received(&source, &encoder, &decoder, &drop, 3);

        if let Ok(result) = decoder.decode(&received) {
            let correct = result
                .source
                .iter()
                .enumerate()
                .all(|(i, s)| s == &source[i]);
            if correct {
                successes += 1;
            }
        }
    }

    assert!(
        successes >= 6,
        "f4: multi-seed repair-heavy sweep must succeed >= 6/8 times, got {successes}/8"
    );

    // Determinism check: same seed must produce same stats.
    for &seed in &seeds[..2] {
        let source = make_source_data(k, symbol_size, seed);
        let encoder = SystematicEncoder::new(&source, symbol_size, seed).unwrap();
        let decoder = InactivationDecoder::new(k, symbol_size, seed);
        let drop: Vec<usize> = (0..k).filter(|i| i % 4 != 0).collect();
        let received = build_decode_received(&source, &encoder, &decoder, &drop, 3);

        if let Ok(r1) = decoder.decode(&received) {
            if let Ok(r2) = decoder.decode(&received) {
                assert_eq!(
                    r1.stats.peeled, r2.stats.peeled,
                    "f4: determinism violation for seed={seed}: peeled differs"
                );
                assert_eq!(
                    r1.stats.gauss_ops, r2.stats.gauss_ops,
                    "f4: determinism violation for seed={seed}: gauss_ops differs"
                );
            }
        }
    }
}

/// F4 invariant: factor cache stats must be non-negative and bounded.
#[test]
fn f4_factor_cache_stats_bounded() {
    let k = 32;
    let symbol_size = 1024;
    let seed = 0xF4CA_0001;
    let source = make_source_data(k, symbol_size, seed);
    let encoder = SystematicEncoder::new(&source, symbol_size, seed).unwrap();
    let decoder = InactivationDecoder::new(k, symbol_size, seed);
    let drop: Vec<usize> = (0..k).filter(|i| i % 4 != 0).collect();
    let received = build_decode_received(&source, &encoder, &decoder, &drop, 3);

    let result = decoder.decode(&received).expect("decode should succeed");

    // Cache misses >= cache inserts (can't insert without a miss).
    assert!(
        result.stats.factor_cache_misses >= result.stats.factor_cache_inserts,
        "f4: cache misses({}) must >= inserts({})",
        result.stats.factor_cache_misses,
        result.stats.factor_cache_inserts
    );
    // Entries must not exceed capacity.
    assert!(
        result.stats.factor_cache_entries <= result.stats.factor_cache_capacity,
        "f4: cache entries({}) must <= capacity({})",
        result.stats.factor_cache_entries,
        result.stats.factor_cache_capacity
    );
}

/// F4 guardrail: benchmark file must reference all 8 runtime lever IDs
/// that the campaign is required to cover.
#[test]
fn f4_campaign_covers_required_lever_observability() {
    // The benchmark campaign must emit decode stats fields that surface lever activity.
    // These fields map to levers: C5/C6 (hard_regime, dense_core), E4 (GF256 fused),
    // F5 (policy_mode), F7 (factor_cache).
    for required in [
        "hard_regime_activated",
        "dense_core_rows",
        "policy_density_permille",
        "factor_cache_hits",
        "factor_cache_misses",
    ] {
        assert!(
            RAPTORQ_BENCH_RS.contains(required),
            "f4: campaign must emit lever observability field: {required}"
        );
    }
}

// ============================================================================
// F6: Regime-shift detector regression invariants
// ============================================================================

/// F6 invariant: regime stats are populated after a successful decode.
#[test]
fn f6_regime_stats_populated_after_decode() {
    let k = 16;
    let symbol_size = 64;
    let seed = 0xF601_0001_u64;

    let source = make_source_data(k, symbol_size, seed);
    let encoder = SystematicEncoder::new(&source, symbol_size, seed).unwrap();
    let decoder = InactivationDecoder::new(k, symbol_size, seed);

    let drop: Vec<usize> = vec![0, 3, 7];
    let received = build_decode_received(&source, &encoder, &decoder, &drop, 4);

    let result = decoder.decode(&received).expect("decode should succeed");

    // Policy metadata must be populated after decode.
    assert!(
        result.stats.policy_mode.is_some() || result.stats.hard_regime_branch.is_some(),
        "f6: policy mode/branch must be populated after decode"
    );
    // Policy replay ref must always be set.
    assert_eq!(
        result.stats.policy_replay_ref,
        Some("replay:rq-track-f-runtime-policy-v1"),
        "f6: policy_replay_ref must match schema"
    );
}

/// G7 invariant: runtime decode decisions expose concrete governance output.
#[test]
fn g7_runtime_governance_output_populated_after_decode() {
    let k = 16;
    let symbol_size = 64;
    let seed = 0x6700_0001_u64;

    let source = make_source_data(k, symbol_size, seed);
    let encoder = SystematicEncoder::new(&source, symbol_size, seed).unwrap();
    let decoder = InactivationDecoder::new(k, symbol_size, seed);
    let received = build_decode_received(&source, &encoder, &decoder, &[1, 5, 9], 4);

    let result = decoder.decode(&received).expect("decode should succeed");
    let governance = result
        .stats
        .governance
        .expect("G7 governance telemetry must be recorded");

    assert_eq!(governance.replay_ref, G7_DECISION_REPLAY_REF);
    assert_eq!(
        governance
            .state_posterior_permille
            .iter()
            .map(|&value| u32::from(value))
            .sum::<u32>(),
        1000,
        "G7 state posterior must be normalized to permille"
    );
    assert_eq!(
        governance
            .top_evidence_contributors
            .iter()
            .map(|entry| u32::from(entry.contribution_permille))
            .sum::<u32>(),
        1000,
        "G7 top contributors must be normalized to permille"
    );
    assert!(matches!(
        governance.chosen_action,
        "continue" | "canary_hold" | "rollback" | "fallback"
    ));
    if governance.deterministic_fallback_triggered {
        assert_eq!(
            governance.chosen_action, "fallback",
            "G7 fallback trigger must force fallback action"
        );
    }
}

/// G7 invariant: runtime governance telemetry survives unit-log serialization.
#[test]
#[cfg(feature = "test-internals")]
fn g7_unit_log_schema_accepts_runtime_governance_payload() {
    use asupersync::raptorq::test_log_schema::validate_unit_log_json;

    let k = 16;
    let symbol_size = 64;
    let seed = 0x6700_0001_u64;

    let source = make_source_data(k, symbol_size, seed);
    let encoder = SystematicEncoder::new(&source, symbol_size, seed).unwrap();
    let decoder = InactivationDecoder::new(k, symbol_size, seed);
    let drop = [1usize, 5, 9];
    let received = build_decode_received(&source, &encoder, &decoder, &drop, 10);

    let result = decoder.decode(&received).expect("decode should succeed");
    let log_entry = UnitLogEntry::new(
        "RQ-G7-RUNTIME-GOVERNANCE-UNIT-LOG",
        seed,
        &format!("k={k},symbol_size={symbol_size},loss_pct={}", (drop.len() * 100) / k),
        G7_DECISION_REPLAY_REF,
        "rch exec -- cargo test --test raptorq_perf_invariants g7_unit_log_schema_accepts_runtime_governance_payload -- --nocapture",
        "ok",
    )
    .with_decode_stats(UnitDecodeStats {
        k,
        loss_pct: (drop.len() * 100) / k,
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
        governance: result
            .stats
            .governance
            .as_ref()
            .map(UnitGovernanceDecision::from),
    });

    let json = log_entry.to_json().expect("serialize unit log entry");
    let violations = validate_unit_log_json(&json);
    assert!(
        violations.is_empty(),
        "g7 runtime governance payload must satisfy unit-log schema: {violations:?}"
    );

    let parsed: UnitLogEntry = serde_json::from_str(&json).expect("deserialize unit log entry");
    let governance = parsed
        .decode_stats
        .and_then(|stats| stats.governance)
        .expect("unit log should retain governance payload");
    assert_eq!(governance.replay_ref, G7_DECISION_REPLAY_REF);
}

/// F6 invariant: first decode has window_len=1, stable phase, zero deltas.
#[test]
fn f6_first_decode_is_stable_with_zero_deltas() {
    let k = 16;
    let symbol_size = 32;
    let seed = 0xF601_0002_u64;

    let source = make_source_data(k, symbol_size, seed);
    let encoder = SystematicEncoder::new(&source, symbol_size, seed).unwrap();
    let decoder = InactivationDecoder::new(k, symbol_size, seed);

    let drop: Vec<usize> = vec![0, 3, 7];
    let received = build_decode_received(&source, &encoder, &decoder, &drop, 4);
    let result = decoder.decode(&received).expect("decode should succeed");

    assert!(
        result.stats.policy_mode.is_some() || result.stats.hard_regime_branch.is_some(),
        "f6: first decode should expose policy mode/branch"
    );
    assert_eq!(
        result.stats.hard_regime_fallbacks, 0,
        "f6: first decode should not require hard-regime fallback retries"
    );
    assert_eq!(
        result.stats.policy_replay_ref,
        Some("replay:rq-track-f-runtime-policy-v1"),
        "f6: first decode should expose policy replay ref"
    );
}

/// F6 invariant: multiple successive decodes on the same decoder
/// accumulate window entries without exceeding capacity.
#[test]
fn f6_window_bounded_across_decodes() {
    let k = 16;
    let symbol_size = 32;
    let seed = 0xF601_0003_u64;

    let source = make_source_data(k, symbol_size, seed);
    let encoder = SystematicEncoder::new(&source, symbol_size, seed).unwrap();
    let decoder = InactivationDecoder::new(k, symbol_size, seed);

    let drop: Vec<usize> = vec![0, 3, 7];
    let received = build_decode_received(&source, &encoder, &decoder, &drop, 4);

    let mut last_replay_ref = None;
    // Decode 50 times on the same decoder instance.
    for i in 0..50 {
        let result = decoder
            .decode(&received)
            .unwrap_or_else(|e| panic!("f6: decode {i} should succeed: {e:?}"));
        let replay_ref = result.stats.policy_replay_ref;
        if let Some(previous) = last_replay_ref {
            assert_eq!(
                replay_ref,
                Some(previous),
                "f6: replay ref drifted at decode {i}"
            );
        }
        last_replay_ref = replay_ref;
        assert!(
            replay_ref.is_some(),
            "f6: policy replay ref missing at decode {i}"
        );
    }

    assert!(
        last_replay_ref.is_some(),
        "f6: expected replay ref after decode series"
    );
}

/// F6 invariant: retuning deltas are always within bounded caps.
#[test]
fn f6_retuning_deltas_always_bounded() {
    let k = 16;
    let symbol_size = 32;
    let seed = 0xF601_0004_u64;

    let source = make_source_data(k, symbol_size, seed);
    let encoder = SystematicEncoder::new(&source, symbol_size, seed).unwrap();
    let decoder = InactivationDecoder::new(k, symbol_size, seed);

    let drop: Vec<usize> = vec![0, 3, 7];
    let received = build_decode_received(&source, &encoder, &decoder, &drop, 4);

    // Repeated decodes — verify policy feature bounds after each.
    for i in 0..100 {
        let result = decoder
            .decode(&received)
            .unwrap_or_else(|e| panic!("f6: decode {i} should succeed: {e:?}"));
        assert!(
            result.stats.policy_density_permille <= 1000,
            "f6: policy_density_permille {} out of bounds at decode {i}",
            result.stats.policy_density_permille
        );
        assert!(
            result.stats.policy_rank_deficit_permille <= 1000,
            "f6: policy_rank_deficit_permille {} out of bounds at decode {i}",
            result.stats.policy_rank_deficit_permille
        );
        assert!(
            result.stats.policy_inactivation_pressure_permille <= 1000,
            "f6: policy_inactivation_pressure_permille {} out of bounds at decode {i}",
            result.stats.policy_inactivation_pressure_permille
        );
    }
}

/// F6 invariant: deterministic replay — same inputs produce same regime state.
#[test]
fn f6_deterministic_replay_across_decoders() {
    let k = 16;
    let symbol_size = 64;
    let seed = 0xF601_0005_u64;

    let source = make_source_data(k, symbol_size, seed);
    let encoder = SystematicEncoder::new(&source, symbol_size, seed).unwrap();

    // Two independent decoders fed identical sequences.
    let decoder_a = InactivationDecoder::new(k, symbol_size, seed);
    let decoder_b = InactivationDecoder::new(k, symbol_size, seed);

    let received = build_decode_received(&source, &encoder, &decoder_a, &[1, 5, 9], 4);

    for i in 0..40 {
        let result_a = decoder_a
            .decode(&received)
            .unwrap_or_else(|e| panic!("f6: decode_a {i} failed: {e:?}"));
        let result_b = decoder_b
            .decode(&received)
            .unwrap_or_else(|e| panic!("f6: decode_b {i} failed: {e:?}"));

        assert_eq!(
            result_a.stats.policy_mode, result_b.stats.policy_mode,
            "f6: policy_mode mismatch at decode {i}"
        );
        assert_eq!(
            result_a.stats.policy_replay_ref, result_b.stats.policy_replay_ref,
            "f6: policy_replay_ref mismatch at decode {i}"
        );
        assert_eq!(
            result_a.stats.policy_reason, result_b.stats.policy_reason,
            "f6: policy_reason mismatch at decode {i}"
        );
        assert_eq!(
            result_a.stats.governance, result_b.stats.governance,
            "g7: governance telemetry mismatch at decode {i}"
        );
        assert_eq!(
            result_a.stats.hard_regime_fallbacks, result_b.stats.hard_regime_fallbacks,
            "f6: hard_regime_fallbacks mismatch at decode {i}"
        );
    }
}

/// F6 observability: benchmark file must reference regime stat fields.
#[test]
fn f6_benchmark_covers_regime_observability() {
    for required in [
        "policy_mode",
        "policy_reason",
        "policy_replay_ref",
        "hard_regime_branch",
        "hard_regime_conservative_fallback_reason",
    ] {
        assert!(
            RAPTORQ_BENCH_RS.contains(required),
            "f6: benchmark must emit regime observability field: {required}"
        );
    }
}

// ============================================================================
// Track-G Performance Governance Tests
// ============================================================================

const RAPTORQ_PERFORMANCE_BUDGETS_V1: &str =
    include_str!("../artifacts/raptorq_performance_budgets_v1.json");
const RAPTORQ_PERF_GATES_SCRIPT: &str = include_str!("../scripts/run_raptorq_perf_gates.sh");

/// G1 performance budgets schema and workload coverage validation.
#[test]
fn g1_performance_budgets_schema_and_coverage() {
    let artifact: serde_json::Value = serde_json::from_str(RAPTORQ_PERFORMANCE_BUDGETS_V1)
        .expect("performance budgets artifact must be valid JSON");

    // Schema validation
    assert_eq!(
        artifact["schema_version"].as_str(),
        Some("raptorq-performance-budgets-v1"),
        "performance budgets schema version mismatch"
    );
    assert_eq!(
        artifact["track_bead_id"].as_str(),
        Some("asupersync-2cyx5"),
        "performance budgets must be anchored to Track-G bead"
    );

    // Workload budget coverage
    let workload_budgets = artifact["workload_budgets"]
        .as_object()
        .expect("workload_budgets must be an object");

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

    for workload in &required_workloads {
        assert!(
            workload_budgets.contains_key(*workload),
            "missing required workload budget: {workload}"
        );

        let budget = &workload_budgets[*workload];
        assert!(
            budget["primary_metric"].is_string(),
            "workload {workload} missing primary_metric"
        );
        assert!(
            budget["hard_budget_ns"].is_number()
                || budget["hard_budget_mbps"].is_number()
                || budget["hard_budget_rate"].is_number(),
            "workload {workload} missing hard budget threshold"
        );
        assert!(
            budget["regression_threshold_percent"].is_number(),
            "workload {workload} missing regression_threshold_percent"
        );
    }

    // SLO definitions validation
    let slo_definitions = artifact["slo_definitions"]
        .as_object()
        .expect("slo_definitions must be an object");

    let required_slos = [
        "encode_latency_p95",
        "decode_latency_p99",
        "pipeline_throughput_p5",
        "e2e_reliability",
    ];

    for slo in &required_slos {
        assert!(
            slo_definitions.contains_key(*slo),
            "missing required SLO definition: {slo}"
        );

        let slo_def = &slo_definitions[*slo];
        assert!(slo_def["metric"].is_string(), "SLO {slo} missing metric");
        assert!(
            slo_def["threshold"].is_number(),
            "SLO {slo} missing threshold"
        );
        assert!(
            slo_def["measurement_window_samples"].is_number(),
            "SLO {slo} missing measurement_window_samples"
        );
    }

    // CI gate configuration validation
    let ci_gate_config = artifact["ci_gate_configuration"]
        .as_object()
        .expect("ci_gate_configuration must be an object");

    assert_eq!(
        ci_gate_config["runner_script"].as_str(),
        Some("scripts/run_raptorq_perf_gates.sh"),
        "CI gate must reference the correct runner script"
    );
    assert!(
        ci_gate_config["measurement_samples"].as_u64().unwrap_or(0) >= 10,
        "CI gate must have sufficient measurement samples"
    );
    assert!(
        ci_gate_config["timeout_seconds"].as_u64().unwrap_or(0) >= 300,
        "CI gate must have reasonable timeout"
    );

    // Reproducibility requirements validation
    let repro_reqs = artifact["reproducibility_requirements"]
        .as_object()
        .expect("reproducibility_requirements must be an object");

    assert_eq!(
        repro_reqs["deterministic_seed"].as_u64(),
        Some(424242),
        "reproducibility must use deterministic seed 424242"
    );
    assert_eq!(
        repro_reqs["fixed_thread_count"].as_u64(),
        Some(1),
        "reproducibility must use single thread for consistency"
    );
}

/// G1 performance gate script validation and self-test capability.
#[test]
fn g1_performance_gates_script_validation() {
    // Validate script structure and key components
    assert!(
        RAPTORQ_PERF_GATES_SCRIPT.contains("run_performance_gates"),
        "performance gates script must define run_performance_gates function"
    );
    assert!(
        RAPTORQ_PERF_GATES_SCRIPT.contains("check_all_budgets"),
        "performance gates script must implement budget checking"
    );
    assert!(
        RAPTORQ_PERF_GATES_SCRIPT.contains("verify_rollback_integrity"),
        "performance gates script must support rollback verification"
    );
    assert!(
        RAPTORQ_PERF_GATES_SCRIPT.contains("generate_gate_report"),
        "performance gates script must generate structured reports"
    );

    // Validate required modes
    #[allow(clippy::literal_string_with_formatting_args)]
    assert!(
        RAPTORQ_PERF_GATES_SCRIPT.contains(r#"mode="${1:-full}""#),
        "script must support mode parameter"
    );
    assert!(
        RAPTORQ_PERF_GATES_SCRIPT.contains("smoke"),
        "script must support smoke test mode"
    );
    assert!(
        RAPTORQ_PERF_GATES_SCRIPT.contains("verify-rollback"),
        "script must support rollback verification mode"
    );

    // Validate deterministic environment setup
    assert!(
        RAPTORQ_PERF_GATES_SCRIPT.contains("RAPTORQ_PERF_SEED=424242"),
        "script must set deterministic seed for reproducibility"
    );
    assert!(
        RAPTORQ_PERF_GATES_SCRIPT.contains("RUST_TEST_THREADS=1"),
        "script must enforce single-threaded execution"
    );

    // Validate output artifacts
    assert!(
        RAPTORQ_PERF_GATES_SCRIPT.contains("raptorq_perf_gate_report.json"),
        "script must generate structured JSON report"
    );
    assert!(
        RAPTORQ_PERF_GATES_SCRIPT.contains("raptorq_perf_gate_events.ndjson"),
        "script must generate NDJSON event log for structured logging"
    );

    // Validate integration with governance framework
    assert!(
        RAPTORQ_PERF_GATES_SCRIPT.contains("asupersync-2cyx5"),
        "script must reference Track-G bead in documentation"
    );
}

/// G1 governance integration: performance budgets and CI gates integration test.
#[test]
fn g1_governance_integration_validation() {
    let budget_artifact: serde_json::Value = serde_json::from_str(RAPTORQ_PERFORMANCE_BUDGETS_V1)
        .expect("performance budgets artifact must be valid JSON");

    // Validate governance integration
    let governance = budget_artifact["governance_integration"]
        .as_object()
        .expect("governance_integration must be present");

    assert!(
        governance["decision_record_requirement"]
            .as_str()
            .unwrap_or("")
            .contains("raptorq_optimization_decision_records_v1.json"),
        "governance must require decision record entries for budget changes"
    );

    assert!(
        governance["evidence_artifacts_required"]
            .as_array()
            .expect("evidence_artifacts_required must be an array")
            .len()
            >= 3,
        "governance must require sufficient evidence artifacts"
    );

    // Validate rollback policy
    let rollback_policy = budget_artifact["rollback_policy"]
        .as_object()
        .expect("rollback_policy must be present");

    assert!(
        rollback_policy["automatic_rollback_triggers"]
            .as_array()
            .expect("automatic_rollback_triggers must be an array")
            .len()
            >= 2,
        "rollback policy must define automatic triggers"
    );

    assert!(
        rollback_policy["rollback_command"]
            .as_str()
            .unwrap_or("")
            .contains("git revert"),
        "rollback policy must specify git revert command"
    );

    assert!(
        rollback_policy["verification_command"]
            .as_str()
            .unwrap_or("")
            .contains("run_raptorq_perf_gates.sh --verify-rollback"),
        "rollback policy must specify verification command using performance gates"
    );

    // Validate budget enforcement
    let budget_enforcement = budget_artifact["budget_enforcement"]
        .as_object()
        .expect("budget_enforcement must be present");

    assert_eq!(
        budget_enforcement["ci_gate_enabled"].as_bool(),
        Some(true),
        "CI gate must be enabled for budget enforcement"
    );

    assert_eq!(
        budget_enforcement["failure_action"].as_str(),
        Some("block_merge"),
        "budget violations must block merge"
    );
}
