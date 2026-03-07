//! Runtime control-seam inventory contract invariants (AA-01.3).

#![allow(missing_docs)]

use serde_json::Value;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

const DOC_PATH: &str = "docs/runtime_control_seam_inventory_contract.md";
const ARTIFACT_PATH: &str = "artifacts/runtime_control_seam_inventory_v1.json";
const WORKLOAD_ARTIFACT_PATH: &str = "artifacts/runtime_workload_corpus_v1.json";
const RUNNER_SCRIPT_PATH: &str = "scripts/run_runtime_control_seam_smoke.sh";

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn load_doc() -> String {
    std::fs::read_to_string(repo_root().join(DOC_PATH))
        .expect("failed to load runtime control seam inventory doc")
}

fn load_artifact() -> Value {
    let raw = std::fs::read_to_string(repo_root().join(ARTIFACT_PATH))
        .expect("failed to load runtime control seam inventory artifact");
    serde_json::from_str(&raw).expect("failed to parse runtime control seam artifact")
}

fn load_workload_artifact() -> Value {
    let raw = std::fs::read_to_string(repo_root().join(WORKLOAD_ARTIFACT_PATH))
        .expect("failed to load runtime workload corpus artifact");
    serde_json::from_str(&raw).expect("failed to parse runtime workload corpus artifact")
}

fn seam_ids(artifact: &Value) -> BTreeSet<String> {
    artifact["seams"]
        .as_array()
        .expect("seams must be array")
        .iter()
        .map(|seam| {
            seam["seam_id"]
                .as_str()
                .expect("seam_id must be string")
                .to_string()
        })
        .collect()
}

fn baseline_table_ids(artifact: &Value) -> BTreeSet<String> {
    artifact["baseline_comparator_table"]
        .as_array()
        .expect("baseline_comparator_table must be array")
        .iter()
        .map(|entry| {
            entry["seam_id"]
                .as_str()
                .expect("table seam_id must be string")
                .to_string()
        })
        .collect()
}

#[test]
fn doc_exists() {
    assert!(
        Path::new(DOC_PATH).exists(),
        "runtime control seam inventory doc must exist"
    );
}

#[test]
fn doc_references_bead() {
    let doc = load_doc();
    assert!(
        doc.contains("asupersync-1508v.1.6"),
        "doc must reference bead id"
    );
}

#[test]
fn doc_has_required_sections() {
    let doc = load_doc();
    let sections = [
        "Purpose",
        "Inventory Scope",
        "EV Ranking Model",
        "Baseline Comparator Table",
        "Comparator-Smoke Runner",
        "Structured Artifact Contract",
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
    let refs = [
        "artifacts/runtime_control_seam_inventory_v1.json",
        "scripts/run_runtime_control_seam_smoke.sh",
        "tests/runtime_control_seam_inventory_contract.rs",
    ];
    for reference in refs {
        assert!(doc.contains(reference), "doc must reference {reference}");
    }
}

#[test]
fn doc_reproduction_command_uses_rch() {
    let doc = load_doc();
    assert!(
        doc.contains(
            "rch exec -- env CARGO_INCREMENTAL=0 CARGO_TARGET_DIR=/tmp/rch-codex-aa013 cargo test --test runtime_control_seam_inventory_contract -- --nocapture"
        ),
        "doc must route heavy validation through rch"
    );
}

#[test]
fn artifact_versions_are_stable() {
    let artifact = load_artifact();
    assert_eq!(
        artifact["contract_version"].as_str(),
        Some("runtime-control-seam-inventory-v1")
    );
    assert_eq!(
        artifact["runner_bundle_schema_version"].as_str(),
        Some("runtime-control-seam-smoke-bundle-v1")
    );
    assert_eq!(
        artifact["runner_report_schema_version"].as_str(),
        Some("runtime-control-seam-smoke-run-report-v1")
    );
    assert_eq!(
        artifact["runner_script"].as_str(),
        Some("scripts/run_runtime_control_seam_smoke.sh")
    );
}

#[test]
fn scoring_model_weights_sum_to_one() {
    let artifact = load_artifact();
    let weights = artifact["scoring_model"]["weights"]
        .as_object()
        .expect("scoring_model.weights must be object");
    let sum: f64 = weights
        .values()
        .map(|value| value.as_f64().expect("weight must be number"))
        .sum();
    assert!(
        (sum - 1.0).abs() < 1e-9,
        "scoring model weights must sum to 1.0; got {sum}"
    );
}

#[test]
fn seam_ids_are_unique_and_expected() {
    let artifact = load_artifact();
    let actual = seam_ids(&artifact);
    let expected: BTreeSet<String> = [
        "AA01-SEAM-SCHED-CANCEL-STREAK",
        "AA01-SEAM-SCHED-GOVERNOR",
        "AA01-SEAM-SCHED-ADAPTIVE-CANCEL",
        "AA01-SEAM-BROWSER-HANDOFF",
        "AA01-SEAM-DEADLINE-MONITOR",
        "AA01-SEAM-ADMISSION-ROOT-LIMITS",
        "AA01-SEAM-LEAK-ESCALATION",
        "AA01-SEAM-RETRY-BACKOFF",
        "AA01-SEAM-HEDGE-DELAY",
        "AA01-SEAM-TRANSPORT-ROUTER",
        "AA01-SEAM-RAPTORQ-DECODER-POLICY",
    ]
    .into_iter()
    .map(ToOwned::to_owned)
    .collect();
    assert_eq!(actual, expected, "seam inventory must remain stable");
}

#[test]
fn baseline_table_covers_all_seams() {
    let artifact = load_artifact();
    assert_eq!(
        baseline_table_ids(&artifact),
        seam_ids(&artifact),
        "baseline comparator table must cover every seam exactly once"
    );
}

#[test]
fn each_seam_has_required_fields() {
    let artifact = load_artifact();
    let required_fields: Vec<String> = artifact["required_seam_fields"]
        .as_array()
        .expect("required_seam_fields must be array")
        .iter()
        .map(|field| {
            field
                .as_str()
                .expect("required field must be string")
                .to_string()
        })
        .collect();

    for seam in artifact["seams"].as_array().expect("seams must be array") {
        for field in &required_fields {
            assert!(
                seam.get(field).is_some(),
                "seam missing required field: {field}"
            );
        }
    }
}

#[test]
fn owner_files_exist() {
    let artifact = load_artifact();
    let root = repo_root();
    for seam in artifact["seams"].as_array().expect("seams must be array") {
        let seam_id = seam["seam_id"].as_str().expect("seam_id must be string");
        let owner_file = seam["owner_file"]
            .as_str()
            .expect("owner_file must be string");
        assert!(
            root.join(owner_file).exists(),
            "owner file for {seam_id} must exist: {owner_file}"
        );
    }
}

#[test]
fn smoke_commands_are_rch_routed() {
    let artifact = load_artifact();
    for seam in artifact["seams"].as_array().expect("seams must be array") {
        let seam_id = seam["seam_id"].as_str().expect("seam_id must be string");
        let command = seam["comparator_smoke_command"]
            .as_str()
            .expect("comparator_smoke_command must be string");
        assert!(
            command.contains("rch exec --") || command.contains("RCH_BIN=rch bash"),
            "smoke command for {seam_id} must be rch-routed: {command}"
        );
    }
}

#[test]
fn workload_ids_reference_known_workload_corpus() {
    let artifact = load_artifact();
    let workload_artifact = load_workload_artifact();
    let known_ids: BTreeSet<String> = workload_artifact["workloads"]
        .as_array()
        .expect("workloads must be array")
        .iter()
        .map(|workload| {
            workload["workload_id"]
                .as_str()
                .expect("workload_id must be string")
                .to_string()
        })
        .collect();

    for seam in artifact["seams"].as_array().expect("seams must be array") {
        let seam_id = seam["seam_id"].as_str().expect("seam_id must be string");
        for workload in seam["workload_ids"]
            .as_array()
            .expect("workload_ids must be array")
        {
            let workload = workload
                .as_str()
                .expect("workload id must be string")
                .to_string();
            assert!(
                known_ids.contains(&workload),
                "seam {seam_id} references unknown workload id: {workload}"
            );
        }
    }
}

#[test]
fn ev_fields_are_present_and_in_range() {
    let artifact = load_artifact();
    for seam in artifact["seams"].as_array().expect("seams must be array") {
        let seam_id = seam["seam_id"].as_str().expect("seam_id must be string");
        let ev = seam["ev"].as_object().expect("ev must be object");

        let impact = ev["impact"].as_i64().expect("impact must be integer");
        let confidence = ev["confidence"]
            .as_i64()
            .expect("confidence must be integer");
        let effort = ev["effort"].as_i64().expect("effort must be integer");
        let adoption_friction = ev["adoption_friction"]
            .as_i64()
            .expect("adoption_friction must be integer");
        let user_visible_benefit = ev["user_visible_benefit"]
            .as_i64()
            .expect("user_visible_benefit must be integer");
        let expected_value_score = ev["expected_value_score"]
            .as_f64()
            .expect("expected_value_score must be number");

        for (field_name, value) in [
            ("impact", impact),
            ("confidence", confidence),
            ("effort", effort),
            ("adoption_friction", adoption_friction),
            ("user_visible_benefit", user_visible_benefit),
        ] {
            assert!(
                (1..=5).contains(&value),
                "{field_name} for {seam_id} must be in [1,5], got {value}"
            );
        }

        assert!(
            (0.0..=5.0).contains(&expected_value_score),
            "expected_value_score for {seam_id} must be in [0,5], got {expected_value_score}"
        );
    }
}

#[test]
fn downstream_beads_are_aa_track_ids() {
    let artifact = load_artifact();
    for seam in artifact["seams"].as_array().expect("seams must be array") {
        let seam_id = seam["seam_id"].as_str().expect("seam_id must be string");
        let downstream = seam["downstream_beads"]
            .as_array()
            .expect("downstream_beads must be array");
        assert!(
            !downstream.is_empty(),
            "{seam_id} must list downstream beads"
        );
        for bead in downstream {
            let bead = bead.as_str().expect("downstream bead must be string");
            assert!(
                bead.starts_with("asupersync-1508v."),
                "downstream bead for {seam_id} must be in AA track namespace: {bead}"
            );
        }
    }
}

#[test]
fn runner_script_exists_and_declares_modes() {
    let root = repo_root();
    let script_path = root.join(RUNNER_SCRIPT_PATH);
    assert!(
        script_path.exists(),
        "runner script must exist: {}",
        script_path.display()
    );
    let script = std::fs::read_to_string(&script_path)
        .expect("failed to read runtime control seam smoke runner script");
    for token in [
        "--dry-run",
        "--execute",
        "runtime-control-seam-smoke-bundle-v1",
        "runtime-control-seam-smoke-run-report-v1",
    ] {
        assert!(
            script.contains(token),
            "runner script missing token: {token}"
        );
    }
}
