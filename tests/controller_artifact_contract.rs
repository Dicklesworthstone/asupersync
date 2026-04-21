#![allow(clippy::all)]
//! Controller artifact contract invariants (AA-02.2).

#![allow(missing_docs)]

use serde_json::Value;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

const DOC_PATH: &str = "docs/controller_artifact_contract.md";
const ARTIFACT_PATH: &str = "artifacts/controller_artifact_contract_v1.json";
const RUNNER_SCRIPT_PATH: &str = "scripts/run_controller_artifact_verifier_smoke.sh";

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn load_doc() -> String {
    std::fs::read_to_string(repo_root().join(DOC_PATH))
        .expect("failed to load controller artifact contract doc")
}

fn load_artifact() -> Value {
    let raw = std::fs::read_to_string(repo_root().join(ARTIFACT_PATH))
        .expect("failed to load controller artifact contract artifact");
    serde_json::from_str(&raw).expect("failed to parse controller artifact contract artifact")
}

fn as_string_set(values: &Value, key: &str) -> BTreeSet<String> {
    values[key]
        .as_array()
        .unwrap_or_else(|| panic!("{key} must be array"))
        .iter()
        .map(|item| {
            item.as_str()
                .unwrap_or_else(|| panic!("{key} item must be string"))
                .to_string()
        })
        .collect()
}

fn verify_manifest_case(
    manifest: &Value,
    required_manifest_fields: &[String],
    required_integrity_fields: &[String],
    required_fallback_fields: &[String],
    runtime_major: i64,
    runtime_minor: i64,
) -> (String, String) {
    for field in required_manifest_fields {
        if manifest.get(field).is_none() || manifest[field].is_null() {
            return (
                "reject_missing_field".to_string(),
                format!("missing_field:{field}"),
            );
        }
    }

    for field in required_fallback_fields {
        if manifest["fallback"].get(field).is_none() || manifest["fallback"][field].is_null() {
            return (
                "reject_missing_field".to_string(),
                format!("missing_field:fallback.{field}"),
            );
        }
    }

    for field in required_integrity_fields {
        if manifest["integrity"].get(field).is_none() || manifest["integrity"][field].is_null() {
            return (
                "reject_missing_field".to_string(),
                format!("missing_field:integrity.{field}"),
            );
        }
    }

    if manifest["manifest_schema_version"].as_str() != Some("controller-artifact-manifest-v1") {
        return (
            "reject_schema_mismatch".to_string(),
            "schema:manifest_version".to_string(),
        );
    }

    let min_major = manifest["snapshot_version_range"]["min"]["major"]
        .as_i64()
        .expect("snapshot_version_range.min.major must be integer");
    let min_minor = manifest["snapshot_version_range"]["min"]["minor"]
        .as_i64()
        .expect("snapshot_version_range.min.minor must be integer");
    let max_major = manifest["snapshot_version_range"]["max"]["major"]
        .as_i64()
        .expect("snapshot_version_range.max.major must be integer");
    let max_minor = manifest["snapshot_version_range"]["max"]["minor"]
        .as_i64()
        .expect("snapshot_version_range.max.minor must be integer");

    let version_outside_major = runtime_major < min_major || runtime_major > max_major;
    let version_below_minor = runtime_major == min_major && runtime_minor < min_minor;
    let version_above_minor = runtime_major == max_major && runtime_minor > max_minor;
    if version_outside_major || version_below_minor || version_above_minor {
        return (
            "reject_version_mismatch".to_string(),
            "compatibility:snapshot_version".to_string(),
        );
    }

    if manifest["integrity"]["hash_chain"]["valid"].as_bool() != Some(true) {
        return (
            "reject_hash_mismatch".to_string(),
            "integrity:hash_chain".to_string(),
        );
    }

    if manifest["integrity"]["signature_chain"]["valid"].as_bool() != Some(true) {
        return (
            "reject_signature_mismatch".to_string(),
            "integrity:signature_chain".to_string(),
        );
    }

    ("accept".to_string(), "none".to_string())
}

#[test]
fn doc_exists() {
    assert!(
        Path::new(DOC_PATH).exists(),
        "controller artifact contract doc must exist"
    );
}

#[test]
fn doc_references_bead() {
    let doc = load_doc();
    assert!(
        doc.contains("asupersync-1508v.2.5"),
        "doc must reference bead id"
    );
}

#[test]
fn doc_has_required_sections() {
    let doc = load_doc();
    let sections = [
        "Purpose",
        "Contract Artifacts",
        "Artifact Manifest Format",
        "Verifier Contract",
        "Required Test and Evidence Matrix",
        "Structured Logging Contract",
        "Smoke Runner",
        "Validation",
        "Cross-References",
    ];

    let mut missing = Vec::new();
    for section in sections {
        if !doc.contains(section) {
            missing.push(section);
        }
    }

    assert!(
        missing.is_empty(),
        "doc missing sections:\n{}",
        missing
            .iter()
            .map(|section| format!("  - {section}"))
            .collect::<Vec<_>>()
            .join("\n")
    );
}

#[test]
fn doc_references_artifact_runner_and_test() {
    let doc = load_doc();
    for reference in [
        "artifacts/controller_artifact_contract_v1.json",
        "scripts/run_controller_artifact_verifier_smoke.sh",
        "tests/controller_artifact_contract.rs",
    ] {
        assert!(doc.contains(reference), "doc must reference {reference}");
    }
}

#[test]
fn doc_reproduction_command_uses_rch() {
    let doc = load_doc();
    assert!(
        doc.contains(
            "rch exec -- env CARGO_INCREMENTAL=0 CARGO_TARGET_DIR=/tmp/rch-codex-aa022 cargo test --test controller_artifact_contract -- --nocapture"
        ),
        "doc must route heavy validation through rch"
    );
}

#[test]
fn artifact_versions_are_stable() {
    let artifact = load_artifact();
    assert_eq!(
        artifact["contract_version"].as_str(),
        Some("controller-artifact-contract-v1")
    );
    assert_eq!(
        artifact["runner_bundle_schema_version"].as_str(),
        Some("controller-artifact-verifier-smoke-bundle-v1")
    );
    assert_eq!(
        artifact["runner_report_schema_version"].as_str(),
        Some("controller-artifact-verifier-smoke-run-report-v1")
    );
    assert_eq!(
        artifact["verifier_schema_version"].as_str(),
        Some("controller-artifact-verifier-v1")
    );
}

#[test]
fn required_manifest_fields_are_stable() {
    let artifact = load_artifact();
    let actual = as_string_set(&artifact, "required_manifest_fields");
    let expected: BTreeSet<String> = [
        "artifact_id",
        "manifest_schema_version",
        "controller_name",
        "controller_version",
        "snapshot_version_range",
        "required_snapshot_fields",
        "target_seams",
        "assumptions",
        "bounds",
        "fallback",
        "payload",
        "integrity",
    ]
    .into_iter()
    .map(ToOwned::to_owned)
    .collect();
    assert_eq!(
        actual, expected,
        "required manifest fields must remain stable"
    );
}

#[test]
fn required_integrity_and_fallback_fields_are_stable() {
    let artifact = load_artifact();

    let integrity_actual = as_string_set(&artifact, "required_integrity_fields");
    let integrity_expected: BTreeSet<String> = ["payload_hash", "hash_chain", "signature_chain"]
        .into_iter()
        .map(ToOwned::to_owned)
        .collect();
    assert_eq!(
        integrity_actual, integrity_expected,
        "required integrity fields must remain stable"
    );

    let fallback_actual = as_string_set(&artifact, "required_fallback_fields");
    let fallback_expected: BTreeSet<String> = [
        "fallback_policy_id",
        "rollback_pointer",
        "activation_conditions",
    ]
    .into_iter()
    .map(ToOwned::to_owned)
    .collect();
    assert_eq!(
        fallback_actual, fallback_expected,
        "required fallback fields must remain stable"
    );
}

#[test]
fn supported_verdicts_cover_required_matrix() {
    let artifact = load_artifact();
    let actual = as_string_set(&artifact, "supported_verdicts");
    let required: BTreeSet<String> = [
        "accept",
        "reject_missing_field",
        "reject_hash_mismatch",
        "reject_signature_mismatch",
        "reject_version_mismatch",
        "reject_schema_mismatch",
    ]
    .into_iter()
    .map(ToOwned::to_owned)
    .collect();
    assert_eq!(actual, required, "supported verdict set must remain stable");
}

#[test]
fn verification_cases_cover_required_outcomes() {
    let artifact = load_artifact();
    let cases = artifact["verification_cases"]
        .as_array()
        .expect("verification_cases must be array");
    let ids: BTreeSet<String> = cases
        .iter()
        .map(|case| {
            case["case_id"]
                .as_str()
                .expect("case_id must be string")
                .to_string()
        })
        .collect();

    let required_ids: BTreeSet<String> = [
        "AA02-CASE-HAPPY-PATH",
        "AA02-CASE-MISSING-FIELD",
        "AA02-CASE-HASH-MISMATCH",
        "AA02-CASE-SIGNATURE-MISMATCH",
        "AA02-CASE-VERSION-MISMATCH",
    ]
    .into_iter()
    .map(ToOwned::to_owned)
    .collect();

    assert_eq!(
        ids, required_ids,
        "verification case matrix must remain stable"
    );
}

#[test]
fn deterministic_verifier_logic_matches_expected_cases() {
    let artifact = load_artifact();

    let required_manifest_fields: Vec<String> = artifact["required_manifest_fields"]
        .as_array()
        .expect("required_manifest_fields must be array")
        .iter()
        .map(|field| {
            field
                .as_str()
                .expect("required manifest field must be string")
                .to_string()
        })
        .collect();

    let required_integrity_fields: Vec<String> = artifact["required_integrity_fields"]
        .as_array()
        .expect("required_integrity_fields must be array")
        .iter()
        .map(|field| {
            field
                .as_str()
                .expect("required integrity field must be string")
                .to_string()
        })
        .collect();

    let required_fallback_fields: Vec<String> = artifact["required_fallback_fields"]
        .as_array()
        .expect("required_fallback_fields must be array")
        .iter()
        .map(|field| {
            field
                .as_str()
                .expect("required fallback field must be string")
                .to_string()
        })
        .collect();

    let runtime_major = artifact["runtime_snapshot_version"]["major"]
        .as_i64()
        .expect("runtime_snapshot_version.major must be integer");
    let runtime_minor = artifact["runtime_snapshot_version"]["minor"]
        .as_i64()
        .expect("runtime_snapshot_version.minor must be integer");

    for case in artifact["verification_cases"]
        .as_array()
        .expect("verification_cases must be array")
    {
        let case_id = case["case_id"].as_str().expect("case_id must be string");
        let manifest = &case["manifest"];
        let expected_verdict = case["expect_verdict"]
            .as_str()
            .expect("expect_verdict must be string");
        let expected_rejection_code = case["expect_rejection_code"]
            .as_str()
            .expect("expect_rejection_code must be string");

        let (actual_verdict, actual_rejection_code) = verify_manifest_case(
            manifest,
            &required_manifest_fields,
            &required_integrity_fields,
            &required_fallback_fields,
            runtime_major,
            runtime_minor,
        );

        assert_eq!(
            actual_verdict, expected_verdict,
            "verdict mismatch for case {case_id}"
        );
        assert_eq!(
            actual_rejection_code, expected_rejection_code,
            "rejection code mismatch for case {case_id}"
        );
    }
}

#[test]
fn structured_log_fields_are_unique_and_nonempty() {
    let artifact = load_artifact();
    let fields = artifact["structured_log_fields_required"]
        .as_array()
        .expect("structured_log_fields_required must be array");

    assert!(
        !fields.is_empty(),
        "structured_log_fields_required must not be empty"
    );

    let mut set = BTreeSet::new();
    for field in fields {
        let field = field
            .as_str()
            .expect("structured log field must be string")
            .to_string();
        assert!(!field.is_empty(), "structured log field must not be empty");
        assert!(
            set.insert(field.clone()),
            "duplicate structured log field: {field}"
        );
    }
}

#[test]
fn runner_script_exists_and_declares_modes_and_schemas() {
    let script_path = repo_root().join(RUNNER_SCRIPT_PATH);
    assert!(
        script_path.exists(),
        "runner script must exist: {}",
        script_path.display()
    );

    let script = std::fs::read_to_string(&script_path)
        .expect("failed to read controller artifact verifier smoke runner script");
    for token in [
        "--list",
        "--case",
        "--dry-run",
        "--execute",
        "controller-artifact-verifier-smoke-bundle-v1",
        "controller-artifact-verifier-smoke-run-report-v1",
    ] {
        assert!(
            script.contains(token),
            "runner script missing token: {token}"
        );
    }
}
