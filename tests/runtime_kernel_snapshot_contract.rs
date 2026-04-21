#![allow(warnings)]
#![allow(clippy::all)]
//! Runtime kernel snapshot contract invariants (AA-02.1).

#![allow(missing_docs)]

use serde_json::Value;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

const DOC_PATH: &str = "docs/runtime_kernel_snapshot_contract.md";
const ARTIFACT_PATH: &str = "artifacts/runtime_kernel_snapshot_contract_v1.json";
const RUNNER_SCRIPT_PATH: &str = "scripts/run_runtime_kernel_snapshot_smoke.sh";
const SOURCE_MODULE_PATH: &str = "src/runtime/kernel.rs";

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn load_doc() -> String {
    std::fs::read_to_string(repo_root().join(DOC_PATH))
        .expect("failed to load runtime kernel snapshot contract doc")
}

fn load_artifact() -> Value {
    let raw = std::fs::read_to_string(repo_root().join(ARTIFACT_PATH))
        .expect("failed to load runtime kernel snapshot contract artifact");
    serde_json::from_str(&raw).expect("failed to parse runtime kernel snapshot contract artifact")
}

fn load_source_module() -> String {
    std::fs::read_to_string(repo_root().join(SOURCE_MODULE_PATH))
        .expect("failed to load runtime kernel source module")
}

fn snapshot_field_names(artifact: &Value) -> BTreeSet<String> {
    artifact["snapshot_schema"]["fields"]
        .as_array()
        .expect("snapshot_schema.fields must be array")
        .iter()
        .map(|field| {
            field["name"]
                .as_str()
                .expect("snapshot field name must be string")
                .to_string()
        })
        .collect()
}

fn required_registration_fields(artifact: &Value) -> BTreeSet<String> {
    artifact["required_registration_fields"]
        .as_array()
        .expect("required_registration_fields must be array")
        .iter()
        .map(|field| {
            field
                .as_str()
                .expect("required registration field must be string")
                .to_string()
        })
        .collect()
}

fn required_metadata_fields(artifact: &Value) -> BTreeSet<String> {
    artifact["required_controller_observation_metadata"]
        .as_array()
        .expect("required_controller_observation_metadata must be array")
        .iter()
        .map(|field| {
            field
                .as_str()
                .expect("required metadata field must be string")
                .to_string()
        })
        .collect()
}

fn validation_rule_codes(artifact: &Value) -> BTreeSet<String> {
    artifact["registration_validation_rules"]
        .as_array()
        .expect("registration_validation_rules must be array")
        .iter()
        .map(|rule| {
            rule["code"]
                .as_str()
                .expect("validation rule code must be string")
                .to_string()
        })
        .collect()
}

#[test]
fn doc_exists() {
    assert!(
        Path::new(DOC_PATH).exists(),
        "runtime kernel snapshot contract doc must exist"
    );
}

#[test]
fn doc_references_bead() {
    let doc = load_doc();
    assert!(
        doc.contains("asupersync-1508v.2.4"),
        "doc must reference bead id"
    );
}

#[test]
fn doc_has_required_sections() {
    let doc = load_doc();
    let sections = [
        "Purpose",
        "Contract Artifacts",
        "Snapshot Scope and Versioning",
        "Required Controller Registration Contract",
        "Mandatory Controller Metadata Surface",
        "Compatibility and Upgrade or Downgrade Semantics",
        "Structured Logging Contract",
        "Comparator-Smoke Runner",
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
        "artifacts/runtime_kernel_snapshot_contract_v1.json",
        "scripts/run_runtime_kernel_snapshot_smoke.sh",
        "tests/runtime_kernel_snapshot_contract.rs",
        "src/runtime/kernel.rs",
    ] {
        assert!(doc.contains(reference), "doc must reference {reference}");
    }
}

#[test]
fn doc_reproduction_command_uses_rch() {
    let doc = load_doc();
    assert!(
        doc.contains(
            "rch exec -- env CARGO_INCREMENTAL=0 CARGO_TARGET_DIR=/tmp/rch-codex-aa021 cargo test --test runtime_kernel_snapshot_contract -- --nocapture"
        ),
        "doc must route heavy validation through rch"
    );
}

#[test]
fn artifact_versions_are_stable() {
    let artifact = load_artifact();
    assert_eq!(
        artifact["contract_version"].as_str(),
        Some("runtime-kernel-snapshot-contract-v1")
    );
    assert_eq!(
        artifact["runner_bundle_schema_version"].as_str(),
        Some("runtime-kernel-snapshot-smoke-bundle-v1")
    );
    assert_eq!(
        artifact["runner_report_schema_version"].as_str(),
        Some("runtime-kernel-snapshot-smoke-run-report-v1")
    );
    assert_eq!(
        artifact["runner_script"].as_str(),
        Some("scripts/run_runtime_kernel_snapshot_smoke.sh")
    );
}

#[test]
fn snapshot_field_catalog_has_expected_stable_names() {
    let artifact = load_artifact();
    let actual = snapshot_field_names(&artifact);
    let expected: BTreeSet<String> = [
        "id",
        "version",
        "timestamp",
        "ready_queue_len",
        "cancel_lane_len",
        "finalize_lane_len",
        "total_tasks",
        "active_regions",
        "cancel_streak_current",
        "cancel_streak_limit",
        "outstanding_obligations",
        "obligation_leak_count",
        "pending_io_registrations",
        "active_timers",
        "worker_count",
        "workers_parked",
        "blocking_threads_active",
        "governor_enabled",
        "adaptive_cancel_enabled",
        "adaptive_epoch",
        "registered_controllers",
        "shadow_controllers",
    ]
    .into_iter()
    .map(ToOwned::to_owned)
    .collect();
    assert_eq!(
        actual, expected,
        "snapshot field catalog must remain stable"
    );
}

#[test]
fn snapshot_field_catalog_is_typed_and_owned() {
    let artifact = load_artifact();
    let root = repo_root();

    for field in artifact["snapshot_schema"]["fields"]
        .as_array()
        .expect("snapshot_schema.fields must be array")
    {
        for key in [
            "name",
            "rust_type",
            "units",
            "owner_symbol",
            "owner_file",
            "update_cadence",
            "purpose",
        ] {
            assert!(field.get(key).is_some(), "field entry missing key: {key}");
        }

        let owner_file = field["owner_file"]
            .as_str()
            .expect("owner_file must be string");
        assert!(
            root.join(owner_file).exists(),
            "owner_file must exist: {owner_file}"
        );
    }
}

#[test]
fn snapshot_fields_are_anchored_to_runtime_kernel_source() {
    let artifact = load_artifact();
    let source = load_source_module();
    for field_name in snapshot_field_names(&artifact) {
        let needle = format!("pub {field_name}:");
        assert!(
            source.contains(&needle),
            "runtime kernel source missing snapshot field declaration: {needle}"
        );
    }
}

#[test]
fn required_registration_field_set_is_complete() {
    let artifact = load_artifact();
    let actual = required_registration_fields(&artifact);
    let expected: BTreeSet<String> = [
        "name",
        "min_version",
        "max_version",
        "required_fields",
        "target_seams",
        "initial_mode",
        "proof_artifact_id",
        "budget",
    ]
    .into_iter()
    .map(ToOwned::to_owned)
    .collect();
    assert_eq!(
        actual, expected,
        "required registration fields must remain stable"
    );
}

#[test]
fn required_controller_metadata_surface_is_complete() {
    let artifact = load_artifact();
    let actual = required_metadata_fields(&artifact);
    let expected: BTreeSet<String> = [
        "decisions_this_epoch",
        "fallback_active",
        "calibration_score",
        "last_action_label",
        "proof_artifact_id",
        "budget_max_decisions_per_epoch",
        "budget_max_decision_latency_us",
    ]
    .into_iter()
    .map(ToOwned::to_owned)
    .collect();
    assert_eq!(
        actual, expected,
        "required controller metadata surface must remain stable"
    );
}

#[test]
fn registration_validation_codes_and_variants_are_complete() {
    let artifact = load_artifact();
    let source = load_source_module();

    let actual_codes = validation_rule_codes(&artifact);
    let expected_codes: BTreeSet<String> = [
        "empty_name",
        "inverted_version_range",
        "incompatible_version",
        "unsupported_fields",
        "no_target_seams",
        "zero_budget",
        "duplicate_name",
    ]
    .into_iter()
    .map(ToOwned::to_owned)
    .collect();
    assert_eq!(
        actual_codes, expected_codes,
        "registration validation codes must remain stable"
    );

    for variant in [
        "RegistrationError::EmptyName",
        "RegistrationError::InvertedVersionRange",
        "RegistrationError::IncompatibleVersion",
        "RegistrationError::UnsupportedFields",
        "RegistrationError::NoTargetSeams",
        "RegistrationError::ZeroBudget",
        "RegistrationError::DuplicateName",
    ] {
        assert!(
            source.contains(variant),
            "runtime kernel source must contain variant token: {variant}"
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
fn smoke_scenarios_are_rch_routed() {
    let artifact = load_artifact();
    let scenarios = artifact["smoke_scenarios"]
        .as_array()
        .expect("smoke_scenarios must be array");
    assert!(
        !scenarios.is_empty(),
        "contract must define at least one smoke scenario"
    );

    for scenario in scenarios {
        let scenario_id = scenario["scenario_id"]
            .as_str()
            .expect("scenario_id must be string");
        let command = scenario["command"]
            .as_str()
            .expect("scenario command must be string");
        assert!(
            command.contains("rch exec --"),
            "scenario {scenario_id} command must use rch: {command}"
        );
    }
}

#[test]
fn downstream_beads_stay_in_aa_track_namespace() {
    let artifact = load_artifact();
    for bead in artifact["downstream_beads"]
        .as_array()
        .expect("downstream_beads must be array")
    {
        let bead = bead.as_str().expect("downstream bead must be string");
        assert!(
            bead.starts_with("asupersync-1508v."),
            "downstream bead must stay in AA namespace: {bead}"
        );
    }
}

#[test]
fn runner_script_exists_and_declares_contract_schemas() {
    let script_path = repo_root().join(RUNNER_SCRIPT_PATH);
    assert!(
        script_path.exists(),
        "runner script must exist: {}",
        script_path.display()
    );

    let script = std::fs::read_to_string(&script_path)
        .expect("failed to read runtime kernel snapshot smoke runner script");
    for token in [
        "--list",
        "--scenario",
        "--dry-run",
        "--execute",
        "runtime-kernel-snapshot-smoke-bundle-v1",
        "runtime-kernel-snapshot-smoke-run-report-v1",
    ] {
        assert!(
            script.contains(token),
            "runner script missing token: {token}"
        );
    }
}
