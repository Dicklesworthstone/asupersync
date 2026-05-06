//! Contract tests for the HTTP/3 and QPACK support matrix.

use serde_json::Value;
use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

fn repo_text(path: &str) -> String {
    fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join(path))
        .unwrap_or_else(|err| panic!("failed to read {path}: {err}"))
}

fn matrix() -> Value {
    serde_json::from_str(&repo_text("artifacts/http3_qpack_support_matrix_v1.json"))
        .expect("HTTP/3 QPACK support matrix must parse")
}

fn feature<'a>(matrix: &'a Value, feature_id: &str) -> &'a Value {
    matrix["feature_matrix"]
        .as_array()
        .expect("feature_matrix must be an array")
        .iter()
        .find(|entry| entry["feature_id"].as_str() == Some(feature_id))
        .unwrap_or_else(|| panic!("missing feature row {feature_id}"))
}

fn assert_contains(haystack: &str, needle: &str, label: &str) {
    assert!(
        haystack.contains(needle),
        "{label} must contain marker {needle:?}"
    );
}

fn assert_not_contains(haystack: &str, needle: &str, label: &str) {
    assert!(
        !haystack.contains(needle),
        "{label} must not contain stale marker {needle:?}"
    );
}

#[test]
fn support_matrix_names_every_http3_qpack_boundary() {
    let matrix = matrix();
    assert_eq!(matrix["contract_version"], "http3-qpack-support-matrix-v1");
    assert_eq!(matrix["bead_id"], "asupersync-bdw1hb");

    let feature_ids = matrix["feature_matrix"]
        .as_array()
        .expect("feature matrix")
        .iter()
        .map(|entry| {
            entry["feature_id"]
                .as_str()
                .expect("feature_id")
                .to_string()
        })
        .collect::<BTreeSet<_>>();

    for required in [
        "h3_settings_control_stream",
        "h3_datagram_extended_connect",
        "qpack_default_static_only",
        "qpack_dynamic_field_sections_opt_in",
        "qpack_huffman_strings",
        "qpack_uni_stream_types",
        "qpack_instruction_stream_state_machine",
        "qpack_blocked_stream_scheduling",
    ] {
        assert!(
            feature_ids.contains(required),
            "matrix missing required feature {required}"
        );
    }

    assert_eq!(
        feature(&matrix, "qpack_default_static_only")["status"],
        "supported_default"
    );
    assert_eq!(
        feature(&matrix, "qpack_dynamic_field_sections_opt_in")["status"],
        "supported_opt_in"
    );
    assert_eq!(
        feature(&matrix, "qpack_instruction_stream_state_machine")["status"],
        "supported_opt_in"
    );
    assert_eq!(
        feature(&matrix, "qpack_blocked_stream_scheduling")["status"],
        "supported_opt_in"
    );
}

#[test]
fn source_markers_back_the_matrix_claims() {
    let matrix = matrix();
    let source = repo_text("src/http/h3_native.rs");

    for row in matrix["feature_matrix"].as_array().expect("feature matrix") {
        for marker in row["source_markers"].as_array().expect("source_markers") {
            let marker = marker.as_str().expect("source marker string");
            assert_contains(&source, marker, row["feature_id"].as_str().unwrap());
        }
    }
}

#[test]
fn docs_state_default_dynamic_and_instruction_stream_boundaries() {
    let readme = repo_text("README.md");
    let integration = repo_text("docs/integration.md");

    for text in [&readme, &integration] {
        assert_contains(text, "default static-only QPACK", "HTTP/3 docs");
        assert_contains(text, "opt-in dynamic QPACK field-section", "HTTP/3 docs");
        assert_contains(
            text,
            "not a claim of h3/quinn drop-in parity",
            "HTTP/3 docs",
        );
        assert_not_contains(
            text,
            "no full QPACK encoder/decoder instruction-stream parity",
            "HTTP/3 docs",
        );
    }

    assert_contains(
        &readme,
        "encoder/decoder instruction-stream processing",
        "README current-state table",
    );
    assert_contains(
        &integration,
        "opt-in dynamic QPACK instruction-stream state machine",
        "integration QPACK stream state",
    );
    assert_contains(
        &integration,
        "artifacts/http3_qpack_support_matrix_v1.json",
        "integration support-matrix pointer",
    );
}

#[test]
fn matrix_advertises_only_native_opt_in_qpack_instruction_parity() {
    let matrix = matrix();
    let summary = matrix["summary"]["parity_boundary"]
        .as_str()
        .expect("parity boundary");
    assert_contains(
        summary,
        "native HTTP/3 state machine supports opt-in QPACK instruction-stream processing",
        "matrix summary",
    );
    assert_contains(
        summary,
        "not a claim of h3/quinn drop-in parity",
        "matrix summary",
    );

    let promoted = [
        feature(&matrix, "qpack_instruction_stream_state_machine"),
        feature(&matrix, "qpack_blocked_stream_scheduling"),
    ];
    for row in promoted {
        assert_eq!(row["support_class"], "production_live_opt_in");
        assert_eq!(row["status"], "supported_opt_in");
    }
}

#[test]
fn proof_artifact_schema_and_runner_cover_promoted_qpack_boundaries() {
    let matrix = matrix();
    let proof = matrix["proof_artifacts"]
        .as_array()
        .expect("proof artifacts")
        .first()
        .expect("proof artifact row");
    let runner_path = proof["runner"].as_str().expect("runner path");
    let runner = repo_text(runner_path);
    let source = repo_text("src/http/h3_native.rs");

    assert_contains(
        &runner,
        "validation_passed",
        "QPACK proof runner validation summary",
    );

    for field in proof["required_fields"]
        .as_array()
        .expect("required fields")
    {
        let field = field.as_str().expect("required field string");
        assert_contains(&source, field, "QPACK proof source row fields");
    }

    for scenario in proof["expected_scenarios"]
        .as_array()
        .expect("expected scenarios")
    {
        let scenario = scenario.as_str().expect("scenario string");
        assert_contains(&runner, scenario, "QPACK proof runner scenarios");
        assert_contains(&source, scenario, "QPACK proof source scenarios");
    }
}
