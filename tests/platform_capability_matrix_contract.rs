#![allow(clippy::nursery, clippy::pedantic, missing_docs)]

use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

const MATRIX_PATH: &str = "artifacts/platform_capability_matrix_v1.json";
const DOCS_PATH: &str = "docs/platform_capability_matrix.md";
const TEST_PATH: &str = "tests/platform_capability_matrix_contract.rs";
const BEAD_ID: &str = "asupersync-idea-wizard-fifth-wave-3gaiun.12";

fn repo_path(relative: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(relative)
}

fn read_repo_file(relative: &str) -> String {
    std::fs::read_to_string(repo_path(relative))
        .unwrap_or_else(|err| panic!("read {relative}: {err}"))
}

fn json_file(relative: &str) -> Value {
    serde_json::from_str(&read_repo_file(relative))
        .unwrap_or_else(|err| panic!("parse {relative}: {err}"))
}

fn array<'a>(value: &'a Value, key: &str) -> &'a [Value] {
    value
        .get(key)
        .and_then(Value::as_array)
        .map_or_else(|| panic!("{key} must be an array"), Vec::as_slice)
}

fn object<'a>(value: &'a Value, key: &str) -> &'a serde_json::Map<String, Value> {
    value
        .get(key)
        .and_then(Value::as_object)
        .unwrap_or_else(|| panic!("{key} must be an object"))
}

fn string<'a>(value: &'a Value, key: &str) -> &'a str {
    let text = value
        .get(key)
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("{key} must be a string"));
    assert!(!text.trim().is_empty(), "{key} must be nonempty");
    text
}

fn bool_field(value: &Value, key: &str) -> bool {
    value
        .get(key)
        .and_then(Value::as_bool)
        .unwrap_or_else(|| panic!("{key} must be a bool"))
}

fn string_set(value: &Value, key: &str) -> BTreeSet<String> {
    array(value, key)
        .iter()
        .map(|entry| {
            entry
                .as_str()
                .unwrap_or_else(|| panic!("{key} entries must be strings"))
                .to_owned()
        })
        .collect()
}

fn matrix() -> Value {
    json_file(MATRIX_PATH)
}

fn platform_ids(matrix: &Value) -> BTreeSet<String> {
    array(matrix, "platforms")
        .iter()
        .map(|platform| string(platform, "platform_id").to_owned())
        .collect()
}

fn status_allows_pass(matrix: &Value) -> BTreeMap<String, bool> {
    array(matrix, "status_catalog")
        .iter()
        .map(|entry| {
            (
                string(entry, "status").to_owned(),
                bool_field(entry, "allows_pass"),
            )
        })
        .collect()
}

fn status_counts_as_supported(matrix: &Value) -> BTreeMap<String, bool> {
    array(matrix, "status_catalog")
        .iter()
        .map(|entry| {
            (
                string(entry, "status").to_owned(),
                bool_field(entry, "counts_as_supported"),
            )
        })
        .collect()
}

fn assert_live_path(path: &str) {
    assert!(repo_path(path).exists(), "path must exist: {path}");
}

#[test]
fn matrix_declares_sources_policy_and_docs_markers() {
    let matrix = matrix();
    assert_eq!(
        matrix.get("schema_version").and_then(Value::as_str),
        Some("platform-capability-matrix-v1")
    );
    assert_eq!(matrix.get("bead_id").and_then(Value::as_str), Some(BEAD_ID));
    assert_eq!(
        matrix.get("artifact_path").and_then(Value::as_str),
        Some(MATRIX_PATH)
    );

    let source = object(&matrix, "source_of_truth");
    assert_eq!(
        source.get("artifact").and_then(Value::as_str),
        Some(MATRIX_PATH)
    );
    assert_eq!(source.get("docs").and_then(Value::as_str), Some(DOCS_PATH));
    assert_eq!(
        source.get("contract_test").and_then(Value::as_str),
        Some(TEST_PATH)
    );
    for path in [MATRIX_PATH, DOCS_PATH, TEST_PATH] {
        assert_live_path(path);
    }

    let policy = matrix
        .get("decision_policy")
        .expect("decision_policy must be present");
    assert!(!bool_field(policy, "skip_is_supported"));
    assert!(!bool_field(policy, "unsupported_is_supported"));
    assert!(!bool_field(policy, "partial_is_supported"));
    assert!(bool_field(policy, "feature_gated_requires_feature_lane"));
    assert!(
        string(policy, "required_no_claim_boundary")
            .contains("Only status=supported rows may include a pass verdict")
    );

    let docs = read_repo_file(DOCS_PATH);
    assert!(
        docs.contains(MATRIX_PATH),
        "docs must link the artifact path"
    );
    assert!(docs.contains(BEAD_ID), "docs must link the owner bead");
    for marker in array(&matrix, "docs_markers") {
        let marker = marker.as_str().expect("docs marker string");
        assert!(docs.contains(marker), "docs missing marker {marker}");
    }

    let validation = object(&matrix, "validation");
    let command = validation
        .get("rch_command")
        .and_then(Value::as_str)
        .expect("validation.rch_command string");
    assert!(command.starts_with("RCH_REQUIRE_REMOTE=1 rch exec -- env "));
    assert!(
        command.contains("cargo test -p asupersync --test platform_capability_matrix_contract")
    );
    assert!(
        command.contains("--no-default-features"),
        "contract proof lane must stay scoped away from optional runtime features"
    );
    assert_eq!(
        validation
            .get("no_local_cargo_fallback")
            .and_then(Value::as_bool),
        Some(true)
    );
}

#[test]
fn capability_rows_cover_required_platforms_and_live_sources() {
    let matrix = matrix();
    let required_platforms = string_set(&matrix, "required_platform_ids");
    assert_eq!(platform_ids(&matrix), required_platforms);
    assert_eq!(required_platforms.len(), 4);

    let required_capabilities = string_set(&matrix, "required_capability_ids");
    let capabilities = array(&matrix, "capabilities");
    let actual_capabilities = capabilities
        .iter()
        .map(|row| string(row, "capability_id").to_owned())
        .collect::<BTreeSet<_>>();
    assert_eq!(actual_capabilities, required_capabilities);

    let required_families = string_set(&matrix, "required_families");
    let actual_families = capabilities
        .iter()
        .map(|row| string(row, "family").to_owned())
        .collect::<BTreeSet<_>>();
    assert_eq!(actual_families, required_families);

    for row in capabilities {
        let capability_id = string(row, "capability_id");
        assert!(
            !array(row, "no_claims").is_empty(),
            "{capability_id} must carry no_claims"
        );
        for source_path in array(row, "source_paths") {
            assert_live_path(source_path.as_str().expect("source path string"));
        }

        let support_rows = array(row, "platform_support");
        let support_ids = support_rows
            .iter()
            .map(|support| string(support, "platform_id").to_owned())
            .collect::<BTreeSet<_>>();
        assert_eq!(
            support_ids, required_platforms,
            "{capability_id} must cover every required platform exactly once"
        );

        for support in support_rows {
            let platform_id = string(support, "platform_id");
            assert!(
                !string(support, "notes").is_empty(),
                "{capability_id}/{platform_id} must explain its status"
            );
            assert!(
                !array(support, "runtime_verdicts").is_empty(),
                "{capability_id}/{platform_id} must list runtime verdicts"
            );
            for evidence_path in array(support, "evidence_refs") {
                assert_live_path(evidence_path.as_str().expect("evidence path string"));
            }
        }
    }
}

#[test]
fn non_supported_rows_cannot_render_as_pass() {
    let matrix = matrix();
    let allows_pass = status_allows_pass(&matrix);
    let counts_as_supported = status_counts_as_supported(&matrix);

    assert_eq!(allows_pass.get("supported"), Some(&true));
    assert_eq!(counts_as_supported.get("supported"), Some(&true));

    for status in ["feature_gated", "partial", "unsupported", "not_applicable"] {
        assert_eq!(allows_pass.get(status), Some(&false));
        assert_eq!(counts_as_supported.get(status), Some(&false));
    }

    for row in array(&matrix, "capabilities") {
        let capability_id = string(row, "capability_id");
        for support in array(row, "platform_support") {
            let platform_id = string(support, "platform_id");
            let status = string(support, "status");
            let status_allows_pass = *allows_pass
                .get(status)
                .unwrap_or_else(|| panic!("{capability_id}/{platform_id} unknown status {status}"));
            let status_counts = *counts_as_supported
                .get(status)
                .unwrap_or_else(|| panic!("{capability_id}/{platform_id} unknown status {status}"));
            let row_counts = bool_field(support, "counts_as_supported");
            let verdicts = array(support, "runtime_verdicts")
                .iter()
                .map(|verdict| verdict.as_str().expect("runtime verdict string"))
                .collect::<BTreeSet<_>>();

            assert_eq!(
                row_counts, status_counts,
                "{capability_id}/{platform_id} counts_as_supported must match status catalog"
            );
            if status_allows_pass {
                assert!(
                    verdicts.contains("pass"),
                    "{capability_id}/{platform_id} supported row must allow pass"
                );
            } else {
                assert!(
                    !verdicts.contains("pass"),
                    "{capability_id}/{platform_id} non-supported row must not allow pass"
                );
                assert!(
                    verdicts.contains("skip") || verdicts.contains("fail"),
                    "{capability_id}/{platform_id} non-supported row must preserve skip or fail evidence"
                );
            }
        }
    }
}

#[test]
fn browser_and_feature_gated_rows_have_explicit_exclusions() {
    let matrix = matrix();
    let mut browser_exclusions = 0usize;
    let mut feature_gated_rows = 0usize;

    for row in array(&matrix, "capabilities") {
        for support in array(row, "platform_support") {
            let platform_id = string(support, "platform_id");
            let status = string(support, "status");
            let notes = string(support, "notes");
            if platform_id == "browser" && matches!(status, "unsupported" | "not_applicable") {
                assert!(
                    notes.contains("Browser") || notes.contains("browser"),
                    "browser exclusion must say browser in notes"
                );
                browser_exclusions += 1;
            }
            if status == "feature_gated" {
                assert!(
                    notes.contains("feature")
                        || notes.contains("package")
                        || notes.contains("host"),
                    "feature-gated row must name feature/package/host condition"
                );
                feature_gated_rows += 1;
            }
        }
    }

    assert!(
        browser_exclusions >= 4,
        "matrix should explicitly exclude native-only surfaces from browser hosts"
    );
    assert!(
        feature_gated_rows >= 4,
        "matrix should preserve feature-gated rows instead of promoting them"
    );
}
