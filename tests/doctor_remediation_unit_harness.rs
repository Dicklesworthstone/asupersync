//! Remediation Unit-Test Suite for DSL, Risk, and Rollback Engines (Track 4.5)
//!
//! Validates remediation recipe DSL parsing, confidence scoring model,
//! risk-band classification, rollback guardrails, idempotence invariants,
//! and fixture-driven regression. Covers happy path, edge cases, and
//! failure modes with deterministic assertions.
//!
//! Bead: asupersync-2b4jj.4.5

#![allow(missing_docs)]
#![cfg(feature = "cli")]

use asupersync::cli::doctor::{
    GuidedRemediationSessionRequest, RemediationConfidenceInput, RemediationPrecondition,
    RemediationRecipe, RemediationRecipeBundle, RemediationRecipeContract, RemediationRollbackPlan,
    build_guided_remediation_patch_plan, compute_remediation_confidence_score,
    compute_remediation_verification_scorecard, parse_remediation_recipe,
    remediation_recipe_bundle, remediation_recipe_contract, remediation_recipe_fixtures,
    remediation_verification_scorecard_thresholds, run_guided_remediation_session,
    run_guided_remediation_session_smoke, run_remediation_recipe_smoke,
    run_remediation_verification_loop_smoke, structured_logging_contract,
    validate_remediation_recipe, validate_remediation_recipe_contract,
    validate_structured_logging_event_stream,
};
use serde::Deserialize;
use std::collections::HashSet;
use std::path::PathBuf;

// ─── Constants ──────────────────────────────────────────────────────

const DOC_PATH: &str = "docs/doctor_remediation_recipe_contract.md";
const FIXTURE_DIR: &str = "tests/fixtures/doctor_remediation_unit";
const FIXTURE_PACK_PATH: &str = "tests/fixtures/doctor_remediation_unit/fixtures.json";
const FIXTURE_PACK_SCHEMA_VERSION: &str = "doctor-remediation-unit-fixture-pack-v1";

/// Risk band identifiers in lexical order.
const RISK_BANDS: [&str; 4] = [
    "critical_risk",
    "elevated_risk",
    "guarded_auto_apply",
    "trusted_auto_apply",
];

/// Allowed fix intents from the contract.
/// Allowed fix intents from the contract (lexical order).
const FIX_INTENTS: [&str; 5] = [
    "add_cancellation_checkpoint",
    "adjust_timeout_budget",
    "enforce_lock_order",
    "harden_retry_backoff",
    "reduce_lock_scope",
];

/// Allowed precondition predicates from the contract.
const PREDICATES: [&str; 5] = ["contains", "eq", "exists", "gte", "lte"];

/// Allowed rollback strategies from the contract.
const ROLLBACK_STRATEGIES: [&str; 3] = [
    "git_apply_reverse_patch",
    "replay_last_green_artifact",
    "restore_backup_snapshot",
];

/// Confidence weight keys from the contract.
const WEIGHT_KEYS: [&str; 4] = [
    "analyzer_confidence",
    "blast_radius",
    "replay_reproducibility",
    "test_coverage_delta",
];

// ─── Fixture types ──────────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize)]
struct RemediationUnitFixturePack {
    schema_version: String,
    description: String,
    fixtures: Vec<RemediationUnitFixture>,
}

#[derive(Debug, Clone, Deserialize)]
struct RemediationUnitFixture {
    fixture_id: String,
    #[allow(dead_code)]
    description: String,
    recipe: RemediationRecipe,
    expected_confidence_score: u8,
    expected_risk_band: String,
    expected_decision: String,
}

// ─── Helpers ────────────────────────────────────────────────────────

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn load_doc() -> String {
    std::fs::read_to_string(repo_root().join(DOC_PATH))
        .expect("failed to load remediation recipe contract doc")
}

fn load_fixture_pack() -> RemediationUnitFixturePack {
    let raw = std::fs::read_to_string(repo_root().join(FIXTURE_PACK_PATH))
        .expect("failed to load fixture pack");
    serde_json::from_str(&raw).expect("failed to parse fixture pack")
}

/// Build a valid recipe from scratch for mutation testing.
fn make_valid_recipe() -> RemediationRecipe {
    RemediationRecipe {
        recipe_id: "recipe-test-001".to_string(),
        finding_id: "doctor-invariant:test/file.rs:warning".to_string(),
        fix_intent: "enforce_lock_order".to_string(),
        preconditions: vec![
            RemediationPrecondition {
                key: "finding_present".to_string(),
                predicate: "eq".to_string(),
                expected_value: "true".to_string(),
                evidence_ref: "evidence-test-001".to_string(),
                required: true,
            },
            RemediationPrecondition {
                key: "repro_available".to_string(),
                predicate: "exists".to_string(),
                expected_value: "true".to_string(),
                evidence_ref: "evidence-test-002".to_string(),
                required: true,
            },
        ],
        rollback: RemediationRollbackPlan {
            strategy: "git_apply_reverse_patch".to_string(),
            rollback_command: "git apply -R test.diff".to_string(),
            verify_command: "cargo test".to_string(),
            timeout_secs: 60,
        },
        confidence_inputs: vec![
            RemediationConfidenceInput {
                key: "analyzer_confidence".to_string(),
                score: 80,
                rationale: "High confidence from invariant oracle.".to_string(),
                evidence_ref: "evidence-analyzer-test-001".to_string(),
            },
            RemediationConfidenceInput {
                key: "blast_radius".to_string(),
                score: 75,
                rationale: "Narrow scope change.".to_string(),
                evidence_ref: "evidence-diff-test-001".to_string(),
            },
            RemediationConfidenceInput {
                key: "replay_reproducibility".to_string(),
                score: 70,
                rationale: "Deterministic replay confirmed.".to_string(),
                evidence_ref: "evidence-replay-test-001".to_string(),
            },
            RemediationConfidenceInput {
                key: "test_coverage_delta".to_string(),
                score: 65,
                rationale: "Good coverage for touched paths.".to_string(),
                evidence_ref: "evidence-tests-test-001".to_string(),
            },
        ],
        override_justification: None,
    }
}

fn all_checkpoint_ids(recipe: &RemediationRecipe) -> Vec<String> {
    let contract = remediation_recipe_contract();
    build_guided_remediation_patch_plan(&contract, recipe)
        .expect("plan")
        .approval_checkpoints
        .iter()
        .map(|checkpoint| checkpoint.checkpoint_id.clone())
        .collect()
}

// ════════════════════════════════════════════════════════════════════
// 1. Contract Validation — Happy Path
// ════════════════════════════════════════════════════════════════════

#[test]
fn contract_validates_canonical() {
    let contract = remediation_recipe_contract();
    validate_remediation_recipe_contract(&contract).expect("canonical contract must be valid");
}

#[test]
fn contract_is_deterministic() {
    let first = remediation_recipe_contract();
    let second = remediation_recipe_contract();
    assert_eq!(first, second, "contract factory must be deterministic");
}

#[test]
fn contract_round_trip_json() {
    let contract = remediation_recipe_contract();
    let json = serde_json::to_string_pretty(&contract).expect("serialize");
    let parsed: RemediationRecipeContract = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(contract, parsed, "JSON round-trip must be lossless");
    validate_remediation_recipe_contract(&parsed).expect("deserialized contract must be valid");
}

#[test]
fn contract_version_matches_expected() {
    let contract = remediation_recipe_contract();
    assert_eq!(contract.contract_version, "doctor-remediation-recipe-v1");
    assert_eq!(contract.logging_contract_version, "doctor-logging-v1");
}

#[test]
fn contract_confidence_weights_sum_to_10000() {
    let contract = remediation_recipe_contract();
    let sum: u32 = contract
        .confidence_weights
        .iter()
        .map(|w| u32::from(w.weight_bps))
        .sum();
    assert_eq!(sum, 10_000, "confidence weights must sum to 10000 bps");
}

#[test]
fn contract_risk_bands_cover_0_to_100_without_gaps() {
    let contract = remediation_recipe_contract();
    let mut ranges: Vec<(u8, u8)> = contract
        .risk_bands
        .iter()
        .map(|b| (b.min_score_inclusive, b.max_score_inclusive))
        .collect();
    ranges.sort_unstable();
    let mut cursor = 0u8;
    for (min_score, max_score) in &ranges {
        assert_eq!(
            *min_score, cursor,
            "risk band gap at {cursor}: expected {cursor}, got {min_score}"
        );
        assert!(
            min_score <= max_score,
            "risk band min > max: {min_score} > {max_score}"
        );
        cursor = max_score.saturating_add(1);
    }
    assert_eq!(
        cursor, 101,
        "risk bands must end at 100 (cursor should be 101)"
    );
}

#[test]
fn contract_all_string_arrays_are_lexically_sorted() {
    fn assert_sorted(items: &[String], label: &str) {
        for window in items.windows(2) {
            assert!(
                window[0] < window[1],
                "{label}: not lexically sorted at ({}, {})",
                window[0],
                window[1]
            );
        }
    }
    let contract = remediation_recipe_contract();
    assert_sorted(&contract.required_recipe_fields, "required_recipe_fields");
    assert_sorted(
        &contract.required_precondition_fields,
        "required_precondition_fields",
    );
    assert_sorted(
        &contract.required_rollback_fields,
        "required_rollback_fields",
    );
    assert_sorted(
        &contract.required_confidence_input_fields,
        "required_confidence_input_fields",
    );
    assert_sorted(&contract.allowed_fix_intents, "allowed_fix_intents");
    assert_sorted(
        &contract.allowed_precondition_predicates,
        "allowed_precondition_predicates",
    );
    assert_sorted(
        &contract.allowed_rollback_strategies,
        "allowed_rollback_strategies",
    );
    let weight_keys: Vec<String> = contract
        .confidence_weights
        .iter()
        .map(|w| w.key.clone())
        .collect();
    assert_sorted(&weight_keys, "confidence_weights.key");
    let band_ids: Vec<String> = contract
        .risk_bands
        .iter()
        .map(|b| b.band_id.clone())
        .collect();
    assert_sorted(&band_ids, "risk_bands.band_id");
}

#[test]
fn contract_required_recipe_fields_are_complete() {
    let contract = remediation_recipe_contract();
    let required = [
        "confidence_inputs",
        "finding_id",
        "fix_intent",
        "preconditions",
        "recipe_id",
        "rollback",
    ];
    for field in &required {
        assert!(
            contract.required_recipe_fields.iter().any(|f| f == field),
            "required_recipe_fields missing {field}"
        );
    }
}

#[test]
fn contract_weight_keys_match_expected() {
    let contract = remediation_recipe_contract();
    let keys: Vec<&str> = contract
        .confidence_weights
        .iter()
        .map(|w| w.key.as_str())
        .collect();
    assert_eq!(keys, WEIGHT_KEYS.to_vec());
}

#[test]
fn contract_fix_intents_match_expected() {
    let contract = remediation_recipe_contract();
    let intents: Vec<&str> = contract
        .allowed_fix_intents
        .iter()
        .map(String::as_str)
        .collect();
    assert_eq!(intents, FIX_INTENTS.to_vec());
}

#[test]
fn contract_predicates_match_expected() {
    let contract = remediation_recipe_contract();
    let predicates: Vec<&str> = contract
        .allowed_precondition_predicates
        .iter()
        .map(String::as_str)
        .collect();
    assert_eq!(predicates, PREDICATES.to_vec());
}

#[test]
fn contract_rollback_strategies_match_expected() {
    let contract = remediation_recipe_contract();
    let strategies: Vec<&str> = contract
        .allowed_rollback_strategies
        .iter()
        .map(String::as_str)
        .collect();
    assert_eq!(strategies, ROLLBACK_STRATEGIES.to_vec());
}

#[test]
fn contract_risk_bands_match_expected() {
    let contract = remediation_recipe_contract();
    let band_ids: Vec<&str> = contract
        .risk_bands
        .iter()
        .map(|b| b.band_id.as_str())
        .collect();
    assert_eq!(band_ids, RISK_BANDS.to_vec());
}

// ════════════════════════════════════════════════════════════════════
// 2. Contract Validation — Error Cases
// ════════════════════════════════════════════════════════════════════

#[test]
fn contract_rejects_wrong_version() {
    let mut contract = remediation_recipe_contract();
    contract.contract_version = "doctor-remediation-recipe-v99".to_string();
    let err =
        validate_remediation_recipe_contract(&contract).expect_err("must reject wrong version");
    assert!(err.contains("unexpected contract_version"), "{err}");
}

#[test]
fn contract_rejects_wrong_logging_version() {
    let mut contract = remediation_recipe_contract();
    contract.logging_contract_version = "doctor-logging-v99".to_string();
    let err = validate_remediation_recipe_contract(&contract)
        .expect_err("must reject wrong logging version");
    assert!(err.contains("unexpected logging_contract_version"), "{err}");
}

#[test]
fn contract_rejects_unsorted_fix_intents() {
    let mut contract = remediation_recipe_contract();
    contract.allowed_fix_intents.swap(0, 1);
    let err = validate_remediation_recipe_contract(&contract)
        .expect_err("must reject unsorted fix intents");
    assert!(err.contains("allowed_fix_intents"), "{err}");
}

#[test]
fn contract_rejects_unsorted_predicates() {
    let mut contract = remediation_recipe_contract();
    contract.allowed_precondition_predicates.swap(0, 1);
    let err = validate_remediation_recipe_contract(&contract)
        .expect_err("must reject unsorted predicates");
    assert!(err.contains("allowed_precondition_predicates"), "{err}");
}

#[test]
fn contract_rejects_unsorted_rollback_strategies() {
    let mut contract = remediation_recipe_contract();
    contract.allowed_rollback_strategies.swap(0, 1);
    let err = validate_remediation_recipe_contract(&contract)
        .expect_err("must reject unsorted rollback strategies");
    assert!(err.contains("allowed_rollback_strategies"), "{err}");
}

#[test]
fn contract_rejects_weight_sum_not_10000() {
    let mut contract = remediation_recipe_contract();
    contract.confidence_weights[0].weight_bps = 1_000; // break the sum
    let err = validate_remediation_recipe_contract(&contract)
        .expect_err("must reject incorrect weight sum");
    assert!(err.contains("must sum to 10000 bps"), "{err}");
}

#[test]
fn contract_rejects_zero_weight_bps() {
    let mut contract = remediation_recipe_contract();
    let orig = contract.confidence_weights[0].weight_bps;
    contract.confidence_weights[0].weight_bps = 0;
    // Fix sum back
    contract.confidence_weights[1].weight_bps += orig;
    let err =
        validate_remediation_recipe_contract(&contract).expect_err("must reject zero weight_bps");
    assert!(err.contains("non-zero weight_bps"), "{err}");
}

#[test]
fn contract_rejects_empty_weight_rationale() {
    let mut contract = remediation_recipe_contract();
    contract.confidence_weights[0].rationale = "   ".to_string();
    let err =
        validate_remediation_recipe_contract(&contract).expect_err("must reject empty rationale");
    assert!(err.contains("must include rationale"), "{err}");
}

#[test]
fn contract_rejects_risk_band_gap() {
    let mut contract = remediation_recipe_contract();
    // Create a gap by changing first band to end at 30 instead of 39
    contract.risk_bands[0].max_score_inclusive = 30;
    let err =
        validate_remediation_recipe_contract(&contract).expect_err("must reject risk band gap");
    assert!(err.contains("without gaps"), "{err}");
}

#[test]
fn contract_rejects_risk_band_min_greater_than_max() {
    let mut contract = remediation_recipe_contract();
    contract.risk_bands[0].min_score_inclusive = 50;
    contract.risk_bands[0].max_score_inclusive = 10;
    let err = validate_remediation_recipe_contract(&contract).expect_err("must reject min > max");
    assert!(
        err.contains("min_score_inclusive > max_score_inclusive") || err.contains("without gaps"),
        "{err}"
    );
}

#[test]
fn contract_rejects_empty_risk_bands() {
    let mut contract = remediation_recipe_contract();
    contract.risk_bands.clear();
    let err =
        validate_remediation_recipe_contract(&contract).expect_err("must reject empty risk bands");
    assert!(err.contains("must be non-empty"), "{err}");
}

#[test]
fn contract_rejects_empty_confidence_weights() {
    let mut contract = remediation_recipe_contract();
    contract.confidence_weights.clear();
    let err =
        validate_remediation_recipe_contract(&contract).expect_err("must reject empty weights");
    assert!(err.contains("must be non-empty"), "{err}");
}

#[test]
fn contract_rejects_missing_required_recipe_field() {
    let mut contract = remediation_recipe_contract();
    contract.required_recipe_fields.retain(|f| f != "rollback");
    let err = validate_remediation_recipe_contract(&contract)
        .expect_err("must reject missing required field");
    assert!(err.contains("missing rollback"), "{err}");
}

#[test]
fn contract_rejects_empty_minimum_reader_version() {
    let mut contract = remediation_recipe_contract();
    contract.compatibility.minimum_reader_version = "  ".to_string();
    let err = validate_remediation_recipe_contract(&contract)
        .expect_err("must reject empty reader version");
    assert!(err.contains("minimum_reader_version"), "{err}");
}

#[test]
fn contract_rejects_unsorted_weight_keys() {
    let mut contract = remediation_recipe_contract();
    contract.confidence_weights.swap(0, 1);
    let err = validate_remediation_recipe_contract(&contract)
        .expect_err("must reject unsorted weight keys");
    assert!(err.contains("confidence_weights.key"), "{err}");
}

// ════════════════════════════════════════════════════════════════════
// 3. Recipe Validation — Happy Path
// ════════════════════════════════════════════════════════════════════

#[test]
fn recipe_validates_canonical_fixtures() {
    let contract = remediation_recipe_contract();
    for fixture in remediation_recipe_fixtures() {
        validate_remediation_recipe(&contract, &fixture.recipe)
            .unwrap_or_else(|err| panic!("fixture {} failed: {err}", fixture.fixture_id));
    }
}

#[test]
fn recipe_validates_helper_recipe() {
    let contract = remediation_recipe_contract();
    let recipe = make_valid_recipe();
    validate_remediation_recipe(&contract, &recipe).expect("helper recipe must validate");
}

#[test]
fn recipe_round_trip_json() {
    let contract = remediation_recipe_contract();
    let recipe = make_valid_recipe();
    let json = serde_json::to_string_pretty(&recipe).expect("serialize");
    let parsed = parse_remediation_recipe(&contract, &json).expect("parse must succeed");
    assert_eq!(recipe, parsed);
}

// ════════════════════════════════════════════════════════════════════
// 4. Recipe Validation — Error Cases
// ════════════════════════════════════════════════════════════════════

#[test]
fn recipe_rejects_bad_recipe_id_format() {
    let contract = remediation_recipe_contract();
    let mut recipe = make_valid_recipe();
    recipe.recipe_id = "badid-001".to_string(); // must start with "recipe-"
    let err = validate_remediation_recipe(&contract, &recipe).expect_err("must reject bad id");
    assert!(err.contains("recipe_id must match recipe-* slug"), "{err}");
}

#[test]
fn recipe_rejects_uppercase_recipe_id() {
    let contract = remediation_recipe_contract();
    let mut recipe = make_valid_recipe();
    recipe.recipe_id = "recipe-Lock-Order".to_string(); // uppercase not slug-like
    let err = validate_remediation_recipe(&contract, &recipe).expect_err("must reject uppercase");
    assert!(err.contains("recipe_id"), "{err}");
}

#[test]
fn recipe_rejects_empty_finding_id() {
    let contract = remediation_recipe_contract();
    let mut recipe = make_valid_recipe();
    recipe.finding_id = String::new();
    let err =
        validate_remediation_recipe(&contract, &recipe).expect_err("must reject empty finding_id");
    assert!(err.contains("finding_id must be non-empty"), "{err}");
}

#[test]
fn recipe_rejects_unknown_fix_intent() {
    let contract = remediation_recipe_contract();
    let mut recipe = make_valid_recipe();
    recipe.fix_intent = "rewrite_everything".to_string();
    let err = validate_remediation_recipe(&contract, &recipe)
        .expect_err("must reject unknown fix_intent");
    assert!(err.contains("unsupported fix_intent"), "{err}");
}

#[test]
fn recipe_rejects_empty_preconditions() {
    let contract = remediation_recipe_contract();
    let mut recipe = make_valid_recipe();
    recipe.preconditions.clear();
    let err = validate_remediation_recipe(&contract, &recipe)
        .expect_err("must reject empty preconditions");
    assert!(err.contains("preconditions must be non-empty"), "{err}");
}

#[test]
fn recipe_rejects_unsorted_precondition_keys() {
    let contract = remediation_recipe_contract();
    let mut recipe = make_valid_recipe();
    recipe.preconditions.swap(0, 1);
    let err = validate_remediation_recipe(&contract, &recipe)
        .expect_err("must reject unsorted preconditions");
    assert!(err.contains("recipe.preconditions.key"), "{err}");
}

#[test]
fn recipe_rejects_unknown_predicate() {
    let contract = remediation_recipe_contract();
    let mut recipe = make_valid_recipe();
    recipe.preconditions[0].predicate = "regex_match".to_string();
    let err =
        validate_remediation_recipe(&contract, &recipe).expect_err("must reject unknown predicate");
    assert!(err.contains("unsupported precondition predicate"), "{err}");
}

#[test]
fn recipe_rejects_empty_expected_value() {
    let contract = remediation_recipe_contract();
    let mut recipe = make_valid_recipe();
    recipe.preconditions[0].expected_value = "  ".to_string();
    let err = validate_remediation_recipe(&contract, &recipe)
        .expect_err("must reject empty expected_value");
    assert!(err.contains("expected_value must be non-empty"), "{err}");
}

#[test]
fn recipe_rejects_required_precondition_without_evidence() {
    let contract = remediation_recipe_contract();
    let mut recipe = make_valid_recipe();
    recipe.preconditions[0].required = true;
    recipe.preconditions[0].evidence_ref = String::new();
    let err = validate_remediation_recipe(&contract, &recipe)
        .expect_err("must reject missing evidence on required precondition");
    assert!(err.contains("must include evidence_ref"), "{err}");
}

#[test]
fn recipe_rejects_unknown_rollback_strategy() {
    let contract = remediation_recipe_contract();
    let mut recipe = make_valid_recipe();
    recipe.rollback.strategy = "nuke_from_orbit".to_string();
    let err = validate_remediation_recipe(&contract, &recipe)
        .expect_err("must reject unknown rollback strategy");
    assert!(err.contains("unsupported rollback strategy"), "{err}");
}

#[test]
fn recipe_rejects_empty_rollback_command() {
    let contract = remediation_recipe_contract();
    let mut recipe = make_valid_recipe();
    recipe.rollback.rollback_command = String::new();
    let err = validate_remediation_recipe(&contract, &recipe)
        .expect_err("must reject empty rollback command");
    assert!(err.contains("rollback commands must be non-empty"), "{err}");
}

#[test]
fn recipe_rejects_empty_verify_command() {
    let contract = remediation_recipe_contract();
    let mut recipe = make_valid_recipe();
    recipe.rollback.verify_command = " ".to_string();
    let err = validate_remediation_recipe(&contract, &recipe)
        .expect_err("must reject empty verify command");
    assert!(err.contains("rollback commands must be non-empty"), "{err}");
}

#[test]
fn recipe_rejects_multiline_rollback_command() {
    let contract = remediation_recipe_contract();
    let mut recipe = make_valid_recipe();
    recipe.rollback.rollback_command = "git apply\n-R patch.diff".to_string();
    let err = validate_remediation_recipe(&contract, &recipe)
        .expect_err("must reject multiline rollback command");
    assert!(err.contains("single-line command"), "{err}");
}

#[test]
fn recipe_rejects_multiline_verify_command() {
    let contract = remediation_recipe_contract();
    let mut recipe = make_valid_recipe();
    recipe.rollback.verify_command = "cargo test\n--lib tests".to_string();
    let err = validate_remediation_recipe(&contract, &recipe)
        .expect_err("must reject multiline verify command");
    assert!(err.contains("single-line command"), "{err}");
}

#[test]
fn recipe_rejects_zero_rollback_timeout() {
    let contract = remediation_recipe_contract();
    let mut recipe = make_valid_recipe();
    recipe.rollback.timeout_secs = 0;
    let err =
        validate_remediation_recipe(&contract, &recipe).expect_err("must reject zero timeout");
    assert!(err.contains("timeout_secs must be > 0"), "{err}");
}

#[test]
fn recipe_rejects_empty_confidence_inputs() {
    let contract = remediation_recipe_contract();
    let mut recipe = make_valid_recipe();
    recipe.confidence_inputs.clear();
    let err = validate_remediation_recipe(&contract, &recipe)
        .expect_err("must reject empty confidence inputs");
    assert!(err.contains("confidence_inputs must be non-empty"), "{err}");
}

#[test]
fn recipe_rejects_unsorted_confidence_input_keys() {
    let contract = remediation_recipe_contract();
    let mut recipe = make_valid_recipe();
    recipe.confidence_inputs.swap(0, 1);
    let err =
        validate_remediation_recipe(&contract, &recipe).expect_err("must reject unsorted inputs");
    assert!(err.contains("recipe.confidence_inputs.key"), "{err}");
}

#[test]
fn recipe_rejects_unknown_confidence_key() {
    let contract = remediation_recipe_contract();
    let mut recipe = make_valid_recipe();
    recipe.confidence_inputs[0].key = "aaaa_unknown_signal".to_string(); // lexically first
    let err = validate_remediation_recipe(&contract, &recipe).expect_err("must reject unknown key");
    assert!(err.contains("missing from contract weights"), "{err}");
}

#[test]
fn recipe_rejects_missing_required_weight() {
    let contract = remediation_recipe_contract();
    let mut recipe = make_valid_recipe();
    recipe
        .confidence_inputs
        .retain(|i| i.key != "test_coverage_delta");
    let err =
        validate_remediation_recipe(&contract, &recipe).expect_err("must reject missing weight");
    assert!(
        err.contains("missing confidence input for required weight test_coverage_delta"),
        "{err}"
    );
}

#[test]
fn recipe_rejects_empty_input_rationale() {
    let contract = remediation_recipe_contract();
    let mut recipe = make_valid_recipe();
    recipe.confidence_inputs[0].rationale = "  ".to_string();
    let err =
        validate_remediation_recipe(&contract, &recipe).expect_err("must reject empty rationale");
    assert!(err.contains("must include rationale"), "{err}");
}

#[test]
fn recipe_rejects_empty_input_evidence_ref() {
    let contract = remediation_recipe_contract();
    let mut recipe = make_valid_recipe();
    recipe.confidence_inputs[0].evidence_ref = String::new();
    let err = validate_remediation_recipe(&contract, &recipe)
        .expect_err("must reject empty evidence_ref");
    assert!(err.contains("must include evidence_ref"), "{err}");
}

#[test]
fn recipe_rejects_empty_override_justification() {
    let contract = remediation_recipe_contract();
    let mut recipe = make_valid_recipe();
    recipe.override_justification = Some("  ".to_string());
    let err =
        validate_remediation_recipe(&contract, &recipe).expect_err("must reject empty override");
    assert!(
        err.contains("override_justification must be non-empty when provided"),
        "{err}"
    );
}

#[test]
fn parse_rejects_invalid_json() {
    let contract = remediation_recipe_contract();
    let err = parse_remediation_recipe(&contract, "not json}").expect_err("must reject bad JSON");
    assert!(err.contains("invalid remediation recipe JSON"), "{err}");
}

// ════════════════════════════════════════════════════════════════════
// 5. Confidence Scoring — Determinism and Risk Bands
// ════════════════════════════════════════════════════════════════════

#[test]
fn confidence_scoring_is_deterministic() {
    let contract = remediation_recipe_contract();
    let recipe = make_valid_recipe();
    let first = compute_remediation_confidence_score(&contract, &recipe).expect("score");
    let second = compute_remediation_confidence_score(&contract, &recipe).expect("score");
    assert_eq!(first, second, "scoring must be deterministic");
}

#[test]
fn confidence_scoring_produces_correct_value() {
    // Manual calculation:
    // analyzer_confidence: 80 * 3200 = 256000
    // blast_radius:        75 * 2400 = 180000
    // replay_reproducibility: 70 * 2200 = 154000
    // test_coverage_delta: 65 * 2200 = 143000
    // total = 733000 / 10000 = 73 (floor)
    let contract = remediation_recipe_contract();
    let recipe = make_valid_recipe();
    let score = compute_remediation_confidence_score(&contract, &recipe).expect("score");
    assert_eq!(score.confidence_score, 73);
    assert_eq!(score.risk_band, "guarded_auto_apply");
    assert!(!score.requires_human_approval);
    assert!(score.allow_auto_apply);
}

#[test]
fn confidence_scoring_weighted_contributions_traces() {
    let contract = remediation_recipe_contract();
    let recipe = make_valid_recipe();
    let score = compute_remediation_confidence_score(&contract, &recipe).expect("score");
    assert_eq!(score.weighted_contributions.len(), WEIGHT_KEYS.len());
    for contribution in &score.weighted_contributions {
        assert!(
            contribution.contains("bps/10000"),
            "contribution missing format: {contribution}"
        );
    }
}

#[test]
fn confidence_scoring_canonical_fixture_guarded_auto_apply() {
    let contract = remediation_recipe_contract();
    let fixtures = remediation_recipe_fixtures();
    let fixture = &fixtures[0]; // fixture-guarded-auto-apply
    let score = compute_remediation_confidence_score(&contract, &fixture.recipe).expect("score");
    assert_eq!(score.confidence_score, fixture.expected_confidence_score);
    assert_eq!(score.risk_band, fixture.expected_risk_band);
    assert_eq!(score.recipe_id, fixture.recipe.recipe_id);
}

#[test]
fn confidence_scoring_canonical_fixture_human_approval() {
    let contract = remediation_recipe_contract();
    let fixtures = remediation_recipe_fixtures();
    let fixture = &fixtures[1]; // fixture-human-approval
    let score = compute_remediation_confidence_score(&contract, &fixture.recipe).expect("score");
    assert_eq!(score.confidence_score, fixture.expected_confidence_score);
    assert_eq!(score.risk_band, fixture.expected_risk_band);
    assert!(score.requires_human_approval);
    assert!(!score.allow_auto_apply);
}

#[test]
fn confidence_scoring_override_disables_auto_apply() {
    let contract = remediation_recipe_contract();
    let mut recipe = make_valid_recipe();
    // Set high scores to land in trusted_auto_apply
    for input in &mut recipe.confidence_inputs {
        input.score = 95;
    }
    recipe.override_justification = Some("Manual review required for safety.".to_string());
    let score = compute_remediation_confidence_score(&contract, &recipe).expect("score");
    assert_eq!(score.risk_band, "trusted_auto_apply");
    assert!(!score.allow_auto_apply, "override must disable auto-apply");
}

#[test]
fn confidence_scoring_all_zeros_lands_in_critical() {
    let contract = remediation_recipe_contract();
    let mut recipe = make_valid_recipe();
    for input in &mut recipe.confidence_inputs {
        input.score = 0;
    }
    let score = compute_remediation_confidence_score(&contract, &recipe).expect("score");
    assert_eq!(score.confidence_score, 0);
    assert_eq!(score.risk_band, "critical_risk");
    assert!(score.requires_human_approval);
    assert!(!score.allow_auto_apply);
}

#[test]
fn confidence_scoring_all_100_lands_in_trusted() {
    let contract = remediation_recipe_contract();
    let mut recipe = make_valid_recipe();
    for input in &mut recipe.confidence_inputs {
        input.score = 100;
    }
    let score = compute_remediation_confidence_score(&contract, &recipe).expect("score");
    assert_eq!(score.confidence_score, 100);
    assert_eq!(score.risk_band, "trusted_auto_apply");
    assert!(!score.requires_human_approval);
    assert!(score.allow_auto_apply);
}

#[test]
fn confidence_scoring_boundary_39_is_critical() {
    let contract = remediation_recipe_contract();
    let mut recipe = make_valid_recipe();
    // Target score = floor(sum / 10000) = 39
    // We need sum = 39 * 10000 = 390000
    // weights: 3200, 2400, 2200, 2200 = 10000
    // Set scores: 39 for each -> 39*3200 + 39*2400 + 39*2200 + 39*2200 = 39*10000 = 390000 / 10000 = 39
    for input in &mut recipe.confidence_inputs {
        input.score = 39;
    }
    let score = compute_remediation_confidence_score(&contract, &recipe).expect("score");
    assert_eq!(score.confidence_score, 39);
    assert_eq!(score.risk_band, "critical_risk");
}

#[test]
fn confidence_scoring_boundary_40_is_elevated() {
    let contract = remediation_recipe_contract();
    let mut recipe = make_valid_recipe();
    for input in &mut recipe.confidence_inputs {
        input.score = 40;
    }
    let score = compute_remediation_confidence_score(&contract, &recipe).expect("score");
    assert_eq!(score.confidence_score, 40);
    assert_eq!(score.risk_band, "elevated_risk");
}

#[test]
fn confidence_scoring_boundary_69_is_elevated() {
    let contract = remediation_recipe_contract();
    let mut recipe = make_valid_recipe();
    for input in &mut recipe.confidence_inputs {
        input.score = 69;
    }
    let score = compute_remediation_confidence_score(&contract, &recipe).expect("score");
    assert_eq!(score.confidence_score, 69);
    assert_eq!(score.risk_band, "elevated_risk");
}

#[test]
fn confidence_scoring_boundary_70_is_guarded() {
    let contract = remediation_recipe_contract();
    let mut recipe = make_valid_recipe();
    for input in &mut recipe.confidence_inputs {
        input.score = 70;
    }
    let score = compute_remediation_confidence_score(&contract, &recipe).expect("score");
    assert_eq!(score.confidence_score, 70);
    assert_eq!(score.risk_band, "guarded_auto_apply");
}

#[test]
fn confidence_scoring_boundary_84_is_guarded() {
    let contract = remediation_recipe_contract();
    let mut recipe = make_valid_recipe();
    for input in &mut recipe.confidence_inputs {
        input.score = 84;
    }
    let score = compute_remediation_confidence_score(&contract, &recipe).expect("score");
    assert_eq!(score.confidence_score, 84);
    assert_eq!(score.risk_band, "guarded_auto_apply");
}

#[test]
fn confidence_scoring_boundary_85_is_trusted() {
    let contract = remediation_recipe_contract();
    let mut recipe = make_valid_recipe();
    for input in &mut recipe.confidence_inputs {
        input.score = 85;
    }
    let score = compute_remediation_confidence_score(&contract, &recipe).expect("score");
    assert_eq!(score.confidence_score, 85);
    assert_eq!(score.risk_band, "trusted_auto_apply");
}

// ════════════════════════════════════════════════════════════════════
// 6. Rollback Guardrails
// ════════════════════════════════════════════════════════════════════

#[test]
fn rollback_validates_all_strategies() {
    let contract = remediation_recipe_contract();
    for strategy in &ROLLBACK_STRATEGIES {
        let mut recipe = make_valid_recipe();
        recipe.rollback.strategy = strategy.to_string();
        validate_remediation_recipe(&contract, &recipe)
            .unwrap_or_else(|err| panic!("strategy {strategy} should be valid: {err}"));
    }
}

#[test]
fn rollback_rejects_carriage_return_in_command() {
    let contract = remediation_recipe_contract();
    let mut recipe = make_valid_recipe();
    recipe.rollback.rollback_command = "git apply\r-R patch.diff".to_string();
    let err =
        validate_remediation_recipe(&contract, &recipe).expect_err("must reject CR in command");
    assert!(err.contains("single-line"), "{err}");
}

#[test]
fn rollback_timeout_u32_max_is_valid() {
    let contract = remediation_recipe_contract();
    let mut recipe = make_valid_recipe();
    recipe.rollback.timeout_secs = u32::MAX;
    validate_remediation_recipe(&contract, &recipe).expect("max timeout must be valid");
}

// ════════════════════════════════════════════════════════════════════
// 7. Bundle and Smoke Flow
// ════════════════════════════════════════════════════════════════════

#[test]
fn bundle_is_deterministic() {
    let first = remediation_recipe_bundle();
    let second = remediation_recipe_bundle();
    assert_eq!(first, second, "bundle factory must be deterministic");
}

#[test]
fn bundle_round_trip_json() {
    let bundle = remediation_recipe_bundle();
    let json = serde_json::to_string_pretty(&bundle).expect("serialize");
    let parsed: RemediationRecipeBundle = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(bundle, parsed);
}

#[test]
fn bundle_fixtures_all_validate() {
    let bundle = remediation_recipe_bundle();
    validate_remediation_recipe_contract(&bundle.contract).expect("bundle contract valid");
    for fixture in &bundle.fixtures {
        validate_remediation_recipe(&bundle.contract, &fixture.recipe)
            .unwrap_or_else(|err| panic!("bundle fixture {} invalid: {err}", fixture.fixture_id));
    }
}

#[test]
fn bundle_fixture_scores_match_expectations() {
    let bundle = remediation_recipe_bundle();
    for fixture in &bundle.fixtures {
        let score = compute_remediation_confidence_score(&bundle.contract, &fixture.recipe)
            .unwrap_or_else(|err| panic!("scoring failed for {}: {err}", fixture.fixture_id));
        assert_eq!(
            score.confidence_score, fixture.expected_confidence_score,
            "fixture {} score mismatch",
            fixture.fixture_id
        );
        assert_eq!(
            score.risk_band, fixture.expected_risk_band,
            "fixture {} risk band mismatch",
            fixture.fixture_id
        );
    }
}

#[test]
fn smoke_flow_is_deterministic() {
    let recipe_contract = remediation_recipe_contract();
    let logging_contract = structured_logging_contract();
    let first = run_remediation_recipe_smoke(&recipe_contract, &logging_contract).expect("smoke");
    let second = run_remediation_recipe_smoke(&recipe_contract, &logging_contract).expect("smoke");
    assert_eq!(first, second, "smoke flow must be deterministic");
}

#[test]
fn smoke_flow_emits_valid_log_events() {
    let recipe_contract = remediation_recipe_contract();
    let logging_contract = structured_logging_contract();
    let events = run_remediation_recipe_smoke(&recipe_contract, &logging_contract).expect("smoke");
    validate_structured_logging_event_stream(&logging_contract, &events)
        .expect("log events must be valid");
}

#[test]
fn smoke_flow_includes_rejection_rationale() {
    let recipe_contract = remediation_recipe_contract();
    let logging_contract = structured_logging_contract();
    let events = run_remediation_recipe_smoke(&recipe_contract, &logging_contract).expect("smoke");
    let has_rejection = events.iter().any(|event| {
        event
            .fields
            .get("rejection_rationale")
            .is_some_and(|v| !v.trim().is_empty())
    });
    assert!(has_rejection, "smoke must include rejection rationale");
}

#[test]
fn smoke_flow_event_types_cover_apply_verify_summary() {
    let recipe_contract = remediation_recipe_contract();
    let logging_contract = structured_logging_contract();
    let events = run_remediation_recipe_smoke(&recipe_contract, &logging_contract).expect("smoke");
    let event_types: HashSet<&str> = events.iter().map(|e| e.event_kind.as_str()).collect();
    for required in [
        "remediation_apply",
        "remediation_verify",
        "verification_summary",
    ] {
        assert!(
            event_types.contains(required),
            "smoke must emit {required} events"
        );
    }
}

#[test]
fn smoke_flow_events_have_correlation_fields() {
    let recipe_contract = remediation_recipe_contract();
    let logging_contract = structured_logging_contract();
    let events = run_remediation_recipe_smoke(&recipe_contract, &logging_contract).expect("smoke");
    for event in &events {
        let fields = &event.fields;
        assert!(
            fields.contains_key("run_id"),
            "event {} missing run_id",
            event.event_kind
        );
        assert!(
            fields.contains_key("scenario_id"),
            "event {} missing scenario_id",
            event.event_kind
        );
        assert!(
            fields.contains_key("trace_id"),
            "event {} missing trace_id",
            event.event_kind
        );
    }
}

// ════════════════════════════════════════════════════════════════════
// 8. Fixture-Driven Regression (External Fixture Pack)
// ════════════════════════════════════════════════════════════════════

#[test]
fn fixture_pack_loads_and_has_correct_schema() {
    let pack = load_fixture_pack();
    assert_eq!(pack.schema_version, FIXTURE_PACK_SCHEMA_VERSION);
    assert!(!pack.description.is_empty());
    assert!(
        pack.fixtures.len() >= 4,
        "fixture pack must have at least 4 fixtures for all risk bands"
    );
}

#[test]
fn fixture_pack_has_unique_ids() {
    let pack = load_fixture_pack();
    let ids: HashSet<&str> = pack
        .fixtures
        .iter()
        .map(|f| f.fixture_id.as_str())
        .collect();
    assert_eq!(ids.len(), pack.fixtures.len(), "fixture IDs must be unique");
}

#[test]
fn fixture_pack_covers_all_risk_bands() {
    let pack = load_fixture_pack();
    let bands: HashSet<&str> = pack
        .fixtures
        .iter()
        .map(|f| f.expected_risk_band.as_str())
        .collect();
    for band in &RISK_BANDS {
        assert!(
            bands.contains(band),
            "fixture pack must cover risk band {band}"
        );
    }
}

#[test]
fn fixture_pack_all_recipes_validate() {
    let contract = remediation_recipe_contract();
    let pack = load_fixture_pack();
    for fixture in &pack.fixtures {
        validate_remediation_recipe(&contract, &fixture.recipe)
            .unwrap_or_else(|err| panic!("fixture {} invalid: {err}", fixture.fixture_id));
    }
}

#[test]
fn fixture_pack_scores_match_expectations() {
    let contract = remediation_recipe_contract();
    let pack = load_fixture_pack();
    for fixture in &pack.fixtures {
        let score = compute_remediation_confidence_score(&contract, &fixture.recipe)
            .unwrap_or_else(|err| panic!("scoring failed for {}: {err}", fixture.fixture_id));
        assert_eq!(
            score.confidence_score, fixture.expected_confidence_score,
            "fixture {} score: expected {}, got {}",
            fixture.fixture_id, fixture.expected_confidence_score, score.confidence_score
        );
        assert_eq!(
            score.risk_band, fixture.expected_risk_band,
            "fixture {} band: expected {}, got {}",
            fixture.fixture_id, fixture.expected_risk_band, score.risk_band
        );
    }
}

#[test]
fn fixture_pack_override_fixture_disables_auto_apply() {
    let contract = remediation_recipe_contract();
    let pack = load_fixture_pack();
    let override_fixtures: Vec<_> = pack
        .fixtures
        .iter()
        .filter(|f| f.recipe.override_justification.is_some())
        .collect();
    assert!(
        !override_fixtures.is_empty(),
        "fixture pack must include override scenario"
    );
    for fixture in &override_fixtures {
        let score = compute_remediation_confidence_score(&contract, &fixture.recipe)
            .unwrap_or_else(|err| panic!("scoring failed for {}: {err}", fixture.fixture_id));
        assert!(
            !score.allow_auto_apply,
            "override fixture {} must have auto_apply=false",
            fixture.fixture_id
        );
    }
}

#[test]
fn fixture_pack_decision_consistency() {
    let contract = remediation_recipe_contract();
    let pack = load_fixture_pack();
    for fixture in &pack.fixtures {
        let score = compute_remediation_confidence_score(&contract, &fixture.recipe)
            .unwrap_or_else(|err| panic!("scoring failed for {}: {err}", fixture.fixture_id));
        let expected_apply = fixture.expected_decision == "apply";
        assert_eq!(
            score.allow_auto_apply, expected_apply,
            "fixture {} decision inconsistency: expected={}, auto_apply={}",
            fixture.fixture_id, fixture.expected_decision, score.allow_auto_apply
        );
    }
}

// ════════════════════════════════════════════════════════════════════
// 9. Idempotence
// ════════════════════════════════════════════════════════════════════

#[test]
fn scoring_idempotent_across_100_iterations() {
    let contract = remediation_recipe_contract();
    let recipe = make_valid_recipe();
    let baseline = compute_remediation_confidence_score(&contract, &recipe).expect("score");
    for i in 0..100 {
        let score = compute_remediation_confidence_score(&contract, &recipe).expect("score");
        assert_eq!(baseline, score, "scoring diverged on iteration {i}");
    }
}

#[test]
fn validation_idempotent_across_repeated_calls() {
    let contract = remediation_recipe_contract();
    let recipe = make_valid_recipe();
    for _ in 0..50 {
        validate_remediation_recipe(&contract, &recipe).expect("must remain valid");
    }
}

// ════════════════════════════════════════════════════════════════════
// 10. Guided Preview/Apply Pipeline
// ════════════════════════════════════════════════════════════════════

#[test]
fn guided_patch_plan_contains_diff_checkpoints_and_guidance() {
    let contract = remediation_recipe_contract();
    let recipe = remediation_recipe_fixtures()
        .first()
        .expect("fixture")
        .recipe
        .clone();
    let plan = build_guided_remediation_patch_plan(&contract, &recipe).expect("plan");

    assert_eq!(
        plan.approval_checkpoints.len(),
        4,
        "must stage 4 checkpoints"
    );
    assert!(
        plan.diff_preview
            .first()
            .is_some_and(|line| line.starts_with("--- a/")),
        "diff preview must include canonical before-hunk header"
    );
    assert!(
        plan.operator_guidance
            .iter()
            .any(|line| line.contains("accept")),
        "operator guidance must explain accept behavior"
    );
    assert!(
        plan.operator_guidance
            .iter()
            .any(|line| line.contains("reject")),
        "operator guidance must explain reject behavior"
    );
    assert!(
        plan.operator_guidance
            .iter()
            .any(|line| line.contains("partial")),
        "operator guidance must explain partial recovery behavior"
    );
}

#[test]
fn guided_session_blocks_apply_without_all_approvals() {
    let recipe_contract = remediation_recipe_contract();
    let logging_contract = structured_logging_contract();
    let recipe = remediation_recipe_fixtures()
        .first()
        .expect("fixture")
        .recipe
        .clone();
    let outcome = run_guided_remediation_session(
        &recipe_contract,
        &logging_contract,
        &recipe,
        &GuidedRemediationSessionRequest {
            run_id: "run-guided-remediation-tests".to_string(),
            scenario_id: "guided-remediation-missing-approvals".to_string(),
            approved_checkpoints: vec!["checkpoint_diff_review".to_string()],
            simulate_apply_failure: false,
            previous_idempotency_key: None,
        },
    )
    .expect("guided session");

    assert_eq!(outcome.apply_status, "blocked_pending_approval");
    assert_eq!(outcome.verify_status, "blocked_pending_approval");
    let apply_event = outcome
        .events
        .iter()
        .find(|event| {
            event.event_kind == "remediation_apply"
                && event.fields.get("mode").is_some_and(|mode| mode == "apply")
        })
        .expect("apply event");
    assert_eq!(
        apply_event.fields.get("mutation_permitted"),
        Some(&"false".to_string())
    );
}

#[test]
fn guided_session_apply_success_creates_rollback_point() {
    let recipe_contract = remediation_recipe_contract();
    let logging_contract = structured_logging_contract();
    let recipe = remediation_recipe_fixtures()
        .first()
        .expect("fixture")
        .recipe
        .clone();
    let outcome = run_guided_remediation_session(
        &recipe_contract,
        &logging_contract,
        &recipe,
        &GuidedRemediationSessionRequest {
            run_id: "run-guided-remediation-tests".to_string(),
            scenario_id: "guided-remediation-success".to_string(),
            approved_checkpoints: all_checkpoint_ids(&recipe),
            simulate_apply_failure: false,
            previous_idempotency_key: None,
        },
    )
    .expect("guided session");

    assert_eq!(outcome.apply_status, "applied");
    assert_eq!(outcome.verify_status, "verified");
    let apply_event = outcome
        .events
        .iter()
        .find(|event| {
            event.event_kind == "remediation_apply"
                && event.fields.get("mode").is_some_and(|mode| mode == "apply")
        })
        .expect("apply event");
    assert_eq!(
        apply_event.fields.get("rollback_point_created"),
        Some(&"true".to_string())
    );
}

#[test]
fn guided_session_idempotency_returns_noop() {
    let recipe_contract = remediation_recipe_contract();
    let logging_contract = structured_logging_contract();
    let recipe = remediation_recipe_fixtures()
        .first()
        .expect("fixture")
        .recipe
        .clone();
    let first = run_guided_remediation_session(
        &recipe_contract,
        &logging_contract,
        &recipe,
        &GuidedRemediationSessionRequest {
            run_id: "run-guided-remediation-tests".to_string(),
            scenario_id: "guided-remediation-idempotent-first".to_string(),
            approved_checkpoints: all_checkpoint_ids(&recipe),
            simulate_apply_failure: false,
            previous_idempotency_key: None,
        },
    )
    .expect("first session");
    let second = run_guided_remediation_session(
        &recipe_contract,
        &logging_contract,
        &recipe,
        &GuidedRemediationSessionRequest {
            run_id: "run-guided-remediation-tests".to_string(),
            scenario_id: "guided-remediation-idempotent-second".to_string(),
            approved_checkpoints: all_checkpoint_ids(&recipe),
            simulate_apply_failure: false,
            previous_idempotency_key: Some(first.patch_plan.idempotency_key.clone()),
        },
    )
    .expect("second session");

    assert_eq!(second.apply_status, "idempotent_noop");
    assert_eq!(second.verify_status, "verified_noop");
    assert_eq!(second.trust_score_before, second.trust_score_after);
}

#[test]
fn guided_session_smoke_is_deterministic_and_covers_success_and_failure() {
    let recipe_contract = remediation_recipe_contract();
    let logging_contract = structured_logging_contract();
    let first = run_guided_remediation_session_smoke(&recipe_contract, &logging_contract)
        .expect("first smoke");
    let second = run_guided_remediation_session_smoke(&recipe_contract, &logging_contract)
        .expect("second smoke");
    assert_eq!(first, second, "guided smoke must be deterministic");
    assert_eq!(first.len(), 2, "guided smoke must emit two scenarios");
    assert!(
        first
            .iter()
            .any(|outcome| outcome.apply_status == "applied"),
        "guided smoke must include success path"
    );
    assert!(
        first
            .iter()
            .any(|outcome| outcome.apply_status == "partial_apply_failed"),
        "guided smoke must include failure path"
    );
    for outcome in &first {
        validate_structured_logging_event_stream(&logging_contract, &outcome.events)
            .expect("guided event stream valid");
        let apply_event = outcome
            .events
            .iter()
            .find(|event| {
                event.event_kind == "remediation_apply"
                    && event.fields.get("mode").is_some_and(|mode| mode == "apply")
            })
            .expect("apply event");
        assert!(
            apply_event.fields.contains_key("decision_checkpoint"),
            "apply event must include decision checkpoint"
        );
        assert!(
            apply_event.fields.contains_key("patch_digest"),
            "apply event must include patch metadata"
        );
        assert!(
            apply_event.fields.contains_key("risk_flags"),
            "apply event must include risk flags"
        );
        assert!(
            apply_event.fields.contains_key("rollback_instructions"),
            "apply event must include rollback instructions"
        );
    }
}

// ════════════════════════════════════════════════════════════════════
// 11. Post-Remediation Verification Loop + Trust Scorecard
// ════════════════════════════════════════════════════════════════════

#[test]
fn verification_scorecard_thresholds_are_sane() {
    let thresholds = remediation_verification_scorecard_thresholds();
    assert!(thresholds.accept_min_score <= 100);
    assert!(thresholds.escalate_below_score <= thresholds.accept_min_score);
    assert!(thresholds.rollback_delta_threshold < 0);
}

#[test]
fn verification_loop_smoke_is_deterministic_and_emits_scorecards() {
    let recipe_contract = remediation_recipe_contract();
    let logging_contract = structured_logging_contract();
    let first = run_remediation_verification_loop_smoke(&recipe_contract, &logging_contract)
        .expect("first smoke");
    let second = run_remediation_verification_loop_smoke(&recipe_contract, &logging_contract)
        .expect("second smoke");
    assert_eq!(
        first, second,
        "verification loop smoke must be deterministic"
    );
    assert_eq!(
        first.entries.len(),
        2,
        "smoke should include two scorecards"
    );
    validate_structured_logging_event_stream(&logging_contract, &first.events)
        .expect("scorecard events must validate");
}

#[test]
fn verification_scorecard_computes_trust_delta_and_recommendations() {
    let recipe_contract = remediation_recipe_contract();
    let logging_contract = structured_logging_contract();
    let sessions = run_guided_remediation_session_smoke(&recipe_contract, &logging_contract)
        .expect("sessions");
    let thresholds = remediation_verification_scorecard_thresholds();
    let report = compute_remediation_verification_scorecard(
        &logging_contract,
        "run-scorecard-tests",
        &sessions,
        &thresholds,
    )
    .expect("scorecard");

    for entry in &report.entries {
        assert_eq!(
            entry.trust_delta,
            i16::from(entry.trust_score_after) - i16::from(entry.trust_score_before),
            "trust_delta must equal after-before for {}",
            entry.scenario_id
        );
    }
    assert!(
        report
            .entries
            .iter()
            .any(|entry| entry.recommendation == "accept"),
        "scorecard must include acceptance path"
    );
    assert!(
        report
            .entries
            .iter()
            .any(|entry| entry.recommendation == "rollback"),
        "scorecard must include rollback path"
    );
}

#[test]
fn verification_scorecard_logs_capture_before_after_unresolved_and_shift() {
    let recipe_contract = remediation_recipe_contract();
    let logging_contract = structured_logging_contract();
    let report = run_remediation_verification_loop_smoke(&recipe_contract, &logging_contract)
        .expect("scorecard smoke");
    let per_scenario = report
        .events
        .iter()
        .filter(|event| {
            event.event_kind == "verification_summary"
                && event
                    .fields
                    .get("scenario_id")
                    .is_some_and(|id| id != "remediation-verification-scorecard")
        })
        .collect::<Vec<_>>();
    assert_eq!(
        per_scenario.len(),
        report.entries.len(),
        "must emit one scorecard event per scenario"
    );
    for event in per_scenario {
        assert!(
            event.fields.contains_key("before_score"),
            "scorecard event missing before_score"
        );
        assert!(
            event.fields.contains_key("after_score"),
            "scorecard event missing after_score"
        );
        assert!(
            event.fields.contains_key("trust_delta"),
            "scorecard event missing trust_delta"
        );
        assert!(
            event.fields.contains_key("unresolved_findings"),
            "scorecard event missing unresolved_findings"
        );
        assert!(
            event.fields.contains_key("confidence_shift"),
            "scorecard event missing confidence_shift"
        );
        assert!(
            event.fields.contains_key("recommendation"),
            "scorecard event missing recommendation"
        );
    }
}

// ════════════════════════════════════════════════════════════════════
// 12. Document Coverage
// ════════════════════════════════════════════════════════════════════

#[test]
fn doc_exists_and_is_non_empty() {
    let doc = load_doc();
    assert!(
        doc.len() > 100,
        "remediation recipe contract doc must be substantive"
    );
}

#[test]
fn doc_mentions_contract_version() {
    let doc = load_doc();
    assert!(
        doc.contains("doctor-remediation-recipe-v1"),
        "doc must reference contract version"
    );
}

#[test]
fn doc_mentions_confidence_scoring_formula() {
    let doc = load_doc();
    assert!(
        doc.contains("10_000") || doc.contains("10000"),
        "doc must reference basis-point denominator"
    );
}

#[test]
fn doc_mentions_risk_bands() {
    let doc = load_doc();
    // Doc must reference at least the critical_risk band (shown in schema example)
    // and the guarded_auto_apply band (used in fixture example).
    assert!(
        doc.contains("critical_risk"),
        "doc must reference critical_risk band"
    );
    assert!(
        doc.contains("guarded_auto_apply"),
        "doc must reference guarded_auto_apply band"
    );
    // Doc must discuss risk band concept
    assert!(
        doc.contains("risk_band") || doc.contains("risk band") || doc.contains("Risk band"),
        "doc must discuss risk band concept"
    );
}

#[test]
fn doc_mentions_determinism() {
    let doc = load_doc();
    assert!(
        doc.contains("deterministic") || doc.contains("Determinism"),
        "doc must discuss determinism"
    );
}

#[test]
fn doc_mentions_validation_rules() {
    let doc = load_doc();
    assert!(
        doc.contains("validate_remediation_recipe_contract"),
        "doc must reference contract validation function"
    );
    assert!(
        doc.contains("validate_remediation_recipe"),
        "doc must reference recipe validation function"
    );
}

#[test]
fn doc_mentions_structured_logging() {
    let doc = load_doc();
    assert!(
        doc.contains("remediation_apply")
            && doc.contains("remediation_verify")
            && doc.contains("verification_summary"),
        "doc must reference structured log event types"
    );
}

#[test]
fn doc_mentions_trust_scorecard_loop() {
    let doc = load_doc();
    assert!(
        doc.contains("compute_remediation_verification_scorecard")
            || doc.contains("trust scorecard")
            || doc.contains("Trust Scorecard"),
        "doc must cover trust scorecard verification loop"
    );
}

#[test]
fn doc_mentions_accept_escalate_rollback_recommendations() {
    let doc = load_doc();
    assert!(
        doc.contains("accept") && doc.contains("escalate") && doc.contains("rollback"),
        "doc must define recommendation thresholds"
    );
}

#[test]
fn doc_mentions_rollback() {
    let doc = load_doc();
    assert!(
        doc.contains("rollback") || doc.contains("Rollback"),
        "doc must discuss rollback behavior"
    );
}

// ════════════════════════════════════════════════════════════════════
// 13. Fixture Directory Integrity
// ════════════════════════════════════════════════════════════════════

#[test]
fn fixture_dir_exists() {
    let path = repo_root().join(FIXTURE_DIR);
    assert!(
        path.is_dir(),
        "fixture directory must exist at {FIXTURE_DIR}",
    );
}

#[test]
fn fixture_pack_file_is_valid_json() {
    let raw = std::fs::read_to_string(repo_root().join(FIXTURE_PACK_PATH))
        .expect("fixture pack must be readable");
    let _: serde_json::Value = serde_json::from_str(&raw).expect("fixture pack must be valid JSON");
}

#[test]
fn fixture_pack_recipes_use_all_fix_intents() {
    let pack = load_fixture_pack();
    let intents: HashSet<&str> = pack
        .fixtures
        .iter()
        .map(|f| f.recipe.fix_intent.as_str())
        .collect();
    // At minimum the pack should use at least 2 distinct fix intents
    assert!(
        intents.len() >= 2,
        "fixture pack should exercise at least 2 fix intents, got: {intents:?}"
    );
}

#[test]
fn fixture_pack_recipes_use_all_rollback_strategies() {
    let pack = load_fixture_pack();
    let strategies: HashSet<&str> = pack
        .fixtures
        .iter()
        .map(|f| f.recipe.rollback.strategy.as_str())
        .collect();
    assert!(
        strategies.len() >= 2,
        "fixture pack should exercise at least 2 rollback strategies, got: {strategies:?}"
    );
}
