#![allow(clippy::all)]
//! Runtime workload corpus contract invariants (AA-01.2).

#![allow(missing_docs)]

use serde_json::Value;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

const DOC_PATH: &str = "docs/runtime_workload_corpus_contract.md";
const ARTIFACT_PATH: &str = "artifacts/runtime_workload_corpus_v1.json";

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn load_doc() -> String {
    std::fs::read_to_string(repo_root().join(DOC_PATH))
        .expect("failed to load runtime workload corpus doc")
}

fn load_artifact() -> Value {
    let raw = std::fs::read_to_string(repo_root().join(ARTIFACT_PATH))
        .expect("failed to load runtime workload corpus artifact");
    serde_json::from_str(&raw).expect("failed to parse runtime workload corpus artifact")
}

fn workload_ids(value: &Value) -> BTreeSet<String> {
    value["workloads"]
        .as_array()
        .expect("workloads must be array")
        .iter()
        .map(|workload| {
            workload["workload_id"]
                .as_str()
                .expect("workload_id must be string")
                .to_string()
        })
        .collect()
}

fn workload_families(value: &Value) -> BTreeSet<String> {
    value["workloads"]
        .as_array()
        .expect("workloads must be array")
        .iter()
        .map(|workload| {
            workload["family"]
                .as_str()
                .expect("family must be string")
                .to_string()
        })
        .collect()
}

fn runtime_profiles(value: &Value) -> BTreeSet<String> {
    value["runtime_profiles"]
        .as_array()
        .expect("runtime_profiles must be array")
        .iter()
        .map(|profile| {
            profile["profile_id"]
                .as_str()
                .expect("profile_id must be string")
                .to_string()
        })
        .collect()
}

#[test]
fn doc_exists() {
    assert!(
        Path::new(DOC_PATH).exists(),
        "runtime workload corpus doc must exist"
    );
}

#[test]
fn doc_references_bead() {
    let doc = load_doc();
    assert!(
        doc.contains("asupersync-1508v.1.5"),
        "doc must reference bead id"
    );
}

#[test]
fn doc_has_required_sections() {
    let doc = load_doc();
    let sections = [
        "Purpose",
        "Corpus Shape",
        "Runtime Profiles",
        "Core Set",
        "Expansion Packs",
        "Reproducibility Bundle Format",
        "Structured Log Requirements",
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
        "artifacts/runtime_workload_corpus_v1.json",
        "scripts/run_runtime_workload_corpus.sh",
        "tests/runtime_workload_corpus_contract.rs",
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
            "rch exec -- env CARGO_INCREMENTAL=0 CARGO_TARGET_DIR=/tmp/rch-pearldog-aa012 cargo test --test runtime_workload_corpus_contract -- --nocapture"
        ),
        "doc must route validation through rch"
    );
}

#[test]
fn artifact_version_and_runner_shape_are_stable() {
    let artifact = load_artifact();
    assert_eq!(
        artifact["contract_version"].as_str(),
        Some("runtime-workload-corpus-v1")
    );
    assert_eq!(
        artifact["bundle_schema_version"].as_str(),
        Some("runtime-workload-bundle-v1")
    );
    assert_eq!(
        artifact["runner_schema_version"].as_str(),
        Some("runtime-workload-run-report-v1")
    );
    assert_eq!(
        artifact["runner_script"].as_str(),
        Some("scripts/run_runtime_workload_corpus.sh")
    );
}

#[test]
fn artifact_structured_log_fields_inventory_is_stable() {
    let artifact = load_artifact();
    let expected: BTreeSet<&str> = [
        "artifact_path",
        "replay_command",
        "runtime_profile",
        "scenario_id",
        "seed",
        "workload_config_ref",
        "workload_id",
    ]
    .into_iter()
    .collect();
    let actual: BTreeSet<&str> = artifact["structured_log_fields_required"]
        .as_array()
        .expect("structured_log_fields_required must be array")
        .iter()
        .map(|field| field.as_str().expect("field must be string"))
        .collect();
    assert_eq!(actual, expected);
}

#[test]
fn artifact_covers_required_runtime_profiles() {
    let artifact = load_artifact();
    let expected: BTreeSet<String> = [
        "bench-release",
        "distributed-shadow",
        "lab-deterministic",
        "native-e2e",
    ]
    .into_iter()
    .map(ToOwned::to_owned)
    .collect();
    assert_eq!(runtime_profiles(&artifact), expected);
}

#[test]
fn artifact_covers_required_workload_families() {
    let artifact = load_artifact();
    let families = workload_families(&artifact);
    let expected: BTreeSet<String> = [
        "bursty",
        "cancellation-heavy",
        "cpu-heavy",
        "distributed-preview",
        "fan-out/fan-in",
        "io-heavy",
        "timer-heavy",
    ]
    .into_iter()
    .map(ToOwned::to_owned)
    .collect();
    assert_eq!(families, expected);
}

#[test]
fn artifact_core_set_and_expansion_packs_reference_known_ids() {
    let artifact = load_artifact();
    let ids = workload_ids(&artifact);

    let core_ids: BTreeSet<String> = artifact["default_core_set"]
        .as_array()
        .expect("default_core_set must be array")
        .iter()
        .map(|item| item.as_str().expect("core item must be string").to_string())
        .collect();
    assert_eq!(
        core_ids.len(),
        7,
        "core set must stay intentionally bounded"
    );
    assert!(
        core_ids.iter().all(|id| ids.contains(id)),
        "all core workload ids must exist in workload inventory"
    );

    for pack in artifact["expansion_packs"]
        .as_array()
        .expect("expansion_packs must be array")
    {
        for id in pack["workload_ids"]
            .as_array()
            .expect("pack workload_ids must be array")
        {
            let id = id.as_str().expect("pack workload id must be string");
            assert!(ids.contains(id), "expansion pack workload must exist: {id}");
            assert!(
                !core_ids.contains(id),
                "expansion-pack workload must not silently enter core set: {id}"
            );
        }
    }
}

#[test]
fn artifact_has_happy_and_pathological_regimes() {
    let artifact = load_artifact();
    let regimes: BTreeSet<&str> = artifact["workloads"]
        .as_array()
        .expect("workloads must be array")
        .iter()
        .map(|workload| workload["regime"].as_str().expect("regime must be string"))
        .collect();
    assert!(regimes.contains("happy_path_throughput"));
    assert!(regimes.contains("pathological_tail_or_failure"));
}

#[test]
fn replay_commands_route_through_bundle_runner() {
    let artifact = load_artifact();
    for workload in artifact["workloads"]
        .as_array()
        .expect("workloads must be array")
    {
        let workload_id = workload["workload_id"]
            .as_str()
            .expect("workload_id must be string");
        let replay_command = workload["replay_command"]
            .as_str()
            .expect("replay_command must be string");
        let expected = format!(
            "RCH_BIN=rch bash ./scripts/run_runtime_workload_corpus.sh --workload {workload_id}"
        );
        assert_eq!(replay_command, expected);
    }
}

#[test]
fn entry_commands_are_rch_routed_and_reference_existing_paths() {
    let artifact = load_artifact();
    let root = repo_root();

    for workload in artifact["workloads"]
        .as_array()
        .expect("workloads must be array")
    {
        let workload_id = workload["workload_id"]
            .as_str()
            .expect("workload_id must be string");
        let runtime_profile = workload["runtime_profile"]
            .as_str()
            .expect("runtime_profile must be string");
        let config_ref = workload["config_ref"]
            .as_str()
            .expect("config_ref must be string");
        let entrypoint_path = workload["entrypoint_path"]
            .as_str()
            .expect("entrypoint_path must be string");
        let entry_command = workload["entry_command"]
            .as_str()
            .expect("entry_command must be string");

        assert!(
            root.join(entrypoint_path).exists(),
            "entrypoint path must exist: {entrypoint_path}"
        );
        assert!(
            entry_command.contains(&format!("WORKLOAD_ID={workload_id}")),
            "entry command must propagate workload id"
        );
        assert!(
            entry_command.contains(&format!("RUNTIME_PROFILE={runtime_profile}")),
            "entry command must propagate runtime profile"
        );
        assert!(
            entry_command.contains("WORKLOAD_CONFIG_REF=") && entry_command.contains(config_ref),
            "entry command must propagate config ref"
        );
        assert!(
            entry_command.contains("rch exec -- cargo")
                || entry_command.contains("RCH_BIN=rch bash ./scripts/"),
            "entry command must route heavy work through rch: {entry_command}"
        );
    }
}

#[test]
fn every_workload_declares_bundle_artifacts_and_evidence() {
    let artifact = load_artifact();

    for workload in artifact["workloads"]
        .as_array()
        .expect("workloads must be array")
    {
        let workload_id = workload["workload_id"]
            .as_str()
            .expect("workload_id must be string");
        let artifacts = workload["expected_artifacts"]
            .as_array()
            .expect("expected_artifacts must be array");
        assert!(
            artifacts.len() >= 2,
            "workload must declare at least bundle manifest + run log: {workload_id}"
        );
        assert!(
            artifacts.iter().any(|artifact| {
                artifact["artifact_id"].as_str() == Some("bundle_manifest")
                    && artifact["path_glob"]
                        .as_str()
                        .unwrap_or_default()
                        .contains(workload_id)
            }),
            "workload must declare bundle manifest artifact: {workload_id}"
        );
        assert!(
            artifacts.iter().any(|artifact| {
                artifact["artifact_id"].as_str() == Some("bundle_log")
                    && artifact["path_glob"]
                        .as_str()
                        .unwrap_or_default()
                        .contains(workload_id)
            }),
            "workload must declare bundle log artifact: {workload_id}"
        );
        for artifact in artifacts {
            assert!(
                artifact["kind"]
                    .as_str()
                    .is_some_and(|kind| !kind.is_empty()),
                "artifact kind must be non-empty for {workload_id}"
            );
            assert!(
                artifact["path_glob"]
                    .as_str()
                    .is_some_and(|path_glob| !path_glob.is_empty()),
                "artifact path_glob must be non-empty for {workload_id}"
            );
        }
        let evidence = workload["expected_evidence"]
            .as_array()
            .expect("expected_evidence must be array");
        assert!(
            !evidence.is_empty(),
            "workload must declare expected evidence outputs: {workload_id}"
        );
    }
}
