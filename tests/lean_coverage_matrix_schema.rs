//! Lean coverage matrix schema validation tests (bd-13aa6).

use conformance::{
    CoverageRowType, CoverageStatus, LeanCoverageMatrix, LEAN_COVERAGE_SCHEMA_VERSION,
};
use serde_json::Value;
use std::collections::BTreeSet;

const SCHEMA_JSON: &str = include_str!("../formal/lean/coverage/lean_coverage_matrix.schema.json");
const SAMPLE_JSON: &str = include_str!("../formal/lean/coverage/lean_coverage_matrix.sample.json");

#[test]
fn sample_matrix_parses_and_validates() {
    let matrix = LeanCoverageMatrix::from_json_str(SAMPLE_JSON).expect("sample must parse");
    matrix
        .validate()
        .expect("sample matrix must satisfy validation rules");
    assert_eq!(matrix.schema_version, LEAN_COVERAGE_SCHEMA_VERSION);
}

#[test]
fn sample_matrix_contains_all_required_row_types() {
    let matrix = LeanCoverageMatrix::from_json_str(SAMPLE_JSON).expect("sample must parse");
    assert!(matrix
        .rows
        .iter()
        .any(|row| row.row_type == CoverageRowType::SemanticRule));
    assert!(matrix
        .rows
        .iter()
        .any(|row| row.row_type == CoverageRowType::Invariant));
    assert!(matrix
        .rows
        .iter()
        .any(|row| row.row_type == CoverageRowType::RefinementObligation));
    assert!(matrix
        .rows
        .iter()
        .any(|row| row.row_type == CoverageRowType::OperationalGate));
}

#[test]
fn sample_matrix_contains_status_model_examples() {
    let matrix = LeanCoverageMatrix::from_json_str(SAMPLE_JSON).expect("sample must parse");
    assert!(matrix
        .rows
        .iter()
        .any(|row| row.status == CoverageStatus::InProgress));
    assert!(matrix
        .rows
        .iter()
        .any(|row| row.status == CoverageStatus::Blocked));
    assert!(matrix
        .rows
        .iter()
        .any(|row| row.status == CoverageStatus::Proven));
    assert!(matrix
        .rows
        .iter()
        .any(|row| row.status == CoverageStatus::ValidatedInCi));
}

#[test]
fn schema_enumerates_required_ontology_values() {
    let schema: Value = serde_json::from_str(SCHEMA_JSON).expect("schema must be valid json");
    let row_type_enum = schema
        .pointer("/$defs/row_type/enum")
        .and_then(Value::as_array)
        .expect("row_type enum must exist");
    let status_enum = schema
        .pointer("/$defs/status/enum")
        .and_then(Value::as_array)
        .expect("status enum must exist");
    let blocker_enum = schema
        .pointer("/$defs/blocker_code/enum")
        .and_then(Value::as_array)
        .expect("blocker_code enum must exist");

    let row_type_values = row_type_enum
        .iter()
        .filter_map(Value::as_str)
        .collect::<BTreeSet<_>>();
    let status_values = status_enum
        .iter()
        .filter_map(Value::as_str)
        .collect::<BTreeSet<_>>();
    let blocker_values = blocker_enum
        .iter()
        .filter_map(Value::as_str)
        .collect::<BTreeSet<_>>();

    assert_eq!(
        row_type_values,
        BTreeSet::from([
            "semantic_rule",
            "invariant",
            "refinement_obligation",
            "operational_gate",
        ])
    );
    assert_eq!(
        status_values,
        BTreeSet::from([
            "not-started",
            "in-progress",
            "blocked",
            "proven",
            "validated-in-ci",
        ])
    );
    assert!(blocker_values.contains("BLK_PROOF_MISSING_LEMMA"));
    assert!(blocker_values.contains("BLK_PROOF_SHAPE_MISMATCH"));
    assert!(blocker_values.contains("BLK_MODEL_GAP"));
    assert!(blocker_values.contains("BLK_IMPL_DIVERGENCE"));
    assert!(blocker_values.contains("BLK_TOOLCHAIN_FAILURE"));
    assert!(blocker_values.contains("BLK_EXTERNAL_DEPENDENCY"));
}
