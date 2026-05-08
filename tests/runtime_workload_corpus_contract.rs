#![allow(warnings)]
#![allow(clippy::all)]
//! Runtime workload corpus contract invariants (AA-01.2).

#![allow(missing_docs)]

use asupersync::lab::replay::{
    CoordinationWorkloadExpansionPack, minimize_coordination_pressure_replay,
    synthesize_coordination_pressure_replay,
};
use serde_json::Value;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Command;

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

fn temp_root(name: &str) -> PathBuf {
    let mut path = std::env::temp_dir();
    path.push(format!(
        "asupersync-runtime-workload-corpus-{name}-{}",
        std::process::id()
    ));
    std::fs::create_dir_all(&path).expect("create temp root");
    path
}

fn run_workload_script(args: &[String]) -> std::process::Output {
    Command::new("bash")
        .arg(repo_root().join("scripts/run_runtime_workload_corpus.sh"))
        .args(args)
        .current_dir(repo_root())
        .output()
        .expect("run workload corpus script")
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
    let core_expected: BTreeSet<String> = [
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
    assert!(
        core_expected.is_subset(&families),
        "core workload families must remain present"
    );
    assert!(
        families.contains("agent-swarm-coordination"),
        "coordination expansion family must be present outside the core denominator"
    );
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
fn coordination_expansion_pack_preserves_core_denominator_and_maps_all_families() {
    let artifact = load_artifact();
    let ids = workload_ids(&artifact);
    let core_ids: BTreeSet<String> = artifact["default_core_set"]
        .as_array()
        .expect("default_core_set must be array")
        .iter()
        .map(|item| item.as_str().expect("core item must be string").to_string())
        .collect();
    let coordination = &artifact["coordination_workload_synthesis"];
    assert_eq!(
        coordination["pack_id"].as_str(),
        Some("agent-swarm-coordination-pressure")
    );
    assert_eq!(coordination["baseline_denominator"].as_bool(), Some(false));
    let rch_summary_fields: BTreeSet<String> = coordination["rch_pressure_summary_fields"]
        .as_array()
        .expect("rch_pressure_summary_fields")
        .iter()
        .map(|field| field.as_str().expect("rch summary field").to_string())
        .collect();
    assert_eq!(
        rch_summary_fields,
        BTreeSet::from([
            "artifact_retrieval_tail_bucket".to_string(),
            "command_class_hashes".to_string(),
            "max_queue_depth".to_string(),
            "proof_fanout_count".to_string(),
            "queue_depth_bucket".to_string(),
            "timeout_or_refusal_reasons".to_string(),
        ])
    );

    let required: BTreeSet<String> = coordination["required_scenario_families"]
        .as_array()
        .expect("required families")
        .iter()
        .map(|family| family.as_str().expect("family string").to_string())
        .collect();
    assert_eq!(
        required,
        BTreeSet::from([
            "artifact_retrieval_tail".to_string(),
            "concurrent_rch_proofs".to_string(),
            "coordination_latency_burst".to_string(),
            "fail_closed_dirty_frontier".to_string(),
            "proof_runner_fanout".to_string(),
            "stale_in_progress_reclaim".to_string(),
            "tracker_lock_contention".to_string(),
        ])
    );

    let mappings = coordination["scenario_family_mapping"]
        .as_array()
        .expect("scenario_family_mapping must be array");
    assert_eq!(mappings.len(), 7);
    for mapping in mappings {
        let workload_id = mapping["workload_id"]
            .as_str()
            .expect("mapping workload_id string");
        assert!(ids.contains(workload_id), "mapped workload must exist");
        assert!(
            !core_ids.contains(workload_id),
            "coordination workload must stay outside the core denominator"
        );
        assert!(
            !mapping["semantic_pressure"]
                .as_array()
                .expect("semantic_pressure array")
                .is_empty(),
            "mapping must declare semantic pressure"
        );
        assert!(
            !mapping["provenance_only_context"]
                .as_array()
                .expect("provenance_only_context array")
                .is_empty(),
            "mapping must declare provenance-only context"
        );
        assert!(
            mapping["replay_command"]
                .as_str()
                .expect("replay command")
                .contains(workload_id)
        );
        assert!(
            mapping["entry_command"]
                .as_str()
                .expect("entry command")
                .contains("--synthesize-coordination-pack")
        );
    }
}

#[test]
fn coordination_workloads_have_stable_commands_and_artifact_globs() {
    let artifact = load_artifact();
    let coordination_workloads: Vec<_> = artifact["workloads"]
        .as_array()
        .expect("workloads")
        .iter()
        .filter(|workload| workload["family"].as_str() == Some("agent-swarm-coordination"))
        .collect();
    assert_eq!(coordination_workloads.len(), 7);

    for workload in coordination_workloads {
        let workload_id = workload["workload_id"].as_str().expect("workload id");
        let replay_command = workload["replay_command"].as_str().expect("replay command");
        assert_eq!(
            replay_command,
            format!(
                "RCH_BIN=rch bash ./scripts/run_runtime_workload_corpus.sh --workload {workload_id}"
            )
        );
        assert!(
            workload["entry_command"]
                .as_str()
                .expect("entry command")
                .contains("RCH_BIN=rch bash ./scripts/run_runtime_workload_corpus.sh --synthesize-coordination-pack"),
            "coordination synthesis entry command must stay rch-routed through the script"
        );
        let artifact_globs: BTreeSet<_> = workload["expected_artifacts"]
            .as_array()
            .expect("expected_artifacts")
            .iter()
            .map(|artifact| artifact["path_glob"].as_str().expect("path_glob"))
            .collect();
        assert!(
            artifact_globs
                .iter()
                .any(|glob| glob.contains("coordination-workload-expansion-pack.json"))
        );
        assert!(
            artifact_globs
                .iter()
                .any(|glob| glob.contains("coordination-scheduler-evidence-inputs.json"))
        );
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
        let entrypoint_kind = workload["entrypoint_kind"]
            .as_str()
            .expect("entrypoint_kind must be string");
        let entry_command = workload["entry_command"]
            .as_str()
            .expect("entry_command must be string");
        let is_coordination = workload["family"].as_str() == Some("agent-swarm-coordination");

        assert!(
            root.join(entrypoint_path).exists(),
            "entrypoint path must exist: {entrypoint_path}"
        );
        if is_coordination {
            assert!(
                entry_command.contains("--synthesize-coordination-pack")
                    && entry_command.contains("--coordination-fixture-id accepted-all-families"),
                "coordination entry command must use deterministic synthesis mode"
            );
        } else {
            assert!(
                entry_command.contains(&format!("WORKLOAD_ID={workload_id}")),
                "entry command must propagate workload id"
            );
            assert!(
                entry_command.contains(&format!("RUNTIME_PROFILE={runtime_profile}")),
                "entry command must propagate runtime profile"
            );
            assert!(
                entry_command.contains("WORKLOAD_CONFIG_REF=")
                    && entry_command.contains(config_ref),
                "entry command must propagate config ref"
            );
        }
        assert!(
            entry_command.contains("rch exec -- env CARGO_TARGET_DIR=")
                || entry_command.contains("RCH_BIN=rch bash ./scripts/"),
            "entry command must route heavy work through rch: {entry_command}"
        );
        if entrypoint_kind == "cargo-test" {
            assert!(
                entry_command.contains("rch exec -- env CARGO_TARGET_DIR="),
                "direct cargo workload commands must set a remote CARGO_TARGET_DIR: {entry_command}"
            );
        }
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

#[test]
fn coordination_fixture_synthesis_emits_deterministic_scheduler_inputs() {
    let root = temp_root("coordination-accepted");
    let out = run_workload_script(&[
        "--synthesize-coordination-pack".into(),
        "--coordination-fixture".into(),
        "--output-root".into(),
        root.to_string_lossy().into_owned(),
    ]);
    assert!(
        out.status.success(),
        "accepted fixture stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let run_dir = root
        .join("coordination-expansion")
        .join("coordination-runtime-fixture-accepted-all-families");
    let pack: Value = serde_json::from_str(
        &std::fs::read_to_string(run_dir.join("coordination-workload-expansion-pack.json"))
            .expect("read expansion pack"),
    )
    .expect("parse expansion pack");
    let evidence: Value = serde_json::from_str(
        &std::fs::read_to_string(run_dir.join("coordination-scheduler-evidence-inputs.json"))
            .expect("read evidence inputs"),
    )
    .expect("parse evidence inputs");
    let report: Value = serde_json::from_str(
        &std::fs::read_to_string(run_dir.join("coordination-workload-synthesis-report.json"))
            .expect("read report"),
    )
    .expect("parse report");
    let summary =
        std::fs::read_to_string(run_dir.join("coordination-workload-synthesis.summary.txt"))
            .expect("read summary");

    assert_eq!(report["status"], "passed");
    assert_eq!(
        pack["source_bundle_hash"],
        "sha256:coordination-runtime-fixture-accepted-all-families"
    );
    assert_eq!(
        pack["missing_scenario_families"].as_array().unwrap().len(),
        0
    );
    assert_eq!(pack["workloads"].as_array().unwrap().len(), 7);
    assert_eq!(evidence["evidence_inputs"].as_array().unwrap().len(), 7);
    assert!(summary.contains("tracker_lock_contention"));
    assert!(summary.contains("coordination_latency_burst"));
    assert!(summary.contains("q04_07"));

    let rch_workload = pack["workloads"]
        .as_array()
        .expect("workloads")
        .iter()
        .find(|workload| workload["scenario_family"] == "concurrent_rch_proofs")
        .expect("rch workload");
    let rch_summary = &rch_workload["pressure_summary"]["rch"];
    assert_eq!(rch_summary["queue_depth_bucket"], "q04_07");
    assert_eq!(rch_summary["max_queue_depth"].as_u64(), Some(5));
    assert_eq!(rch_summary["proof_fanout_count"].as_u64(), Some(1));
    assert_eq!(
        rch_summary["artifact_retrieval_tail_bucket"],
        "artifact_tail_unknown"
    );
    assert_eq!(
        rch_summary["timeout_or_refusal_reasons"]
            .as_array()
            .expect("timeout/refusal reasons")
            .len(),
        0
    );
    let command_hashes = rch_summary["command_class_hashes"]
        .as_array()
        .expect("command hashes");
    assert_eq!(command_hashes.len(), 1);
    assert!(
        command_hashes[0]
            .as_str()
            .expect("command hash")
            .starts_with("cmdclass:")
    );

    let evidence_rch = evidence["evidence_inputs"]
        .as_array()
        .expect("evidence inputs")
        .iter()
        .find(|input| input["scenario_family"] == "concurrent_rch_proofs")
        .expect("rch evidence input");
    assert_eq!(
        evidence_rch["pressure_summary"]["rch"]["queue_depth_bucket"],
        "q04_07"
    );
    assert_eq!(
        report["rch_pressure_summary"]["queue_depth_bucket"],
        "q04_07"
    );

    for workload in pack["workloads"].as_array().expect("workloads") {
        assert!(
            workload["source_bundle_hash"]
                .as_str()
                .expect("source bundle hash")
                .starts_with("sha256:")
        );
        assert!(
            !workload["source_hashes"]
                .as_array()
                .expect("source hashes")
                .is_empty()
        );
        assert!(
            workload["source_hashes"].as_array().unwrap()[0]
                .as_str()
                .unwrap()
                .starts_with("sha256:")
        );
        assert!(
            !workload["semantic_pressure"]
                .as_array()
                .expect("semantic pressure")
                .is_empty()
        );
        assert!(
            !workload["provenance_only_context"]
                .as_array()
                .expect("provenance context")
                .is_empty()
        );
        assert!(
            workload["replay_command"]
                .as_str()
                .expect("replay command")
                .starts_with(
                    "RCH_BIN=rch bash ./scripts/run_runtime_workload_corpus.sh --workload"
                )
        );
        assert!(
            workload["expected_artifact_globs"]
                .as_array()
                .expect("artifact globs")
                .iter()
                .any(|glob| glob
                    .as_str()
                    .unwrap()
                    .contains("coordination-workload-expansion-pack.json"))
        );
    }
}

#[test]
fn coordination_expansion_pack_replays_through_lab_hook() {
    let root = temp_root("coordination-lab-replay");
    let out = run_workload_script(&[
        "--synthesize-coordination-pack".into(),
        "--coordination-fixture".into(),
        "--output-root".into(),
        root.to_string_lossy().into_owned(),
    ]);
    assert!(
        out.status.success(),
        "accepted fixture stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let pack_path = root
        .join("coordination-expansion")
        .join("coordination-runtime-fixture-accepted-all-families")
        .join("coordination-workload-expansion-pack.json");
    let pack: CoordinationWorkloadExpansionPack =
        serde_json::from_str(&std::fs::read_to_string(pack_path).expect("read coordination pack"))
            .expect("parse coordination pack into lab replay type");

    let plan = synthesize_coordination_pressure_replay(0xA5A0_0104, &pack)
        .expect("coordination pack should synthesize replay stimuli");
    assert_eq!(plan.stimuli.len(), 7);
    assert_eq!(plan.log.scenario_id, "coordination-pressure-replay");
    assert_eq!(plan.log.seed, 0xA5A0_0104);
    assert_eq!(
        plan.log.source_bundle_hash,
        "sha256:coordination-runtime-fixture-accepted-all-families"
    );
    assert_eq!(plan.log.event_count, 7);
    assert_eq!(plan.log.synthesized_task_count, 15);
    assert_eq!(plan.log.queue_dimension, 14);
    assert_eq!(plan.log.timer_dimension, 11);
    assert_eq!(plan.log.cancel_dimension, 2);
    assert_eq!(plan.log.artifact_delay_dimension, 9);
    assert_ne!(plan.log.trace_fingerprint, 0);
    let artifact_tail = plan
        .stimuli
        .iter()
        .find(|stimulus| stimulus.scenario_family == "artifact_retrieval_tail")
        .expect("artifact retrieval tail replay stimulus");
    assert_eq!(artifact_tail.timer_ticks, 3);
    assert_eq!(artifact_tail.artifact_delay_ticks, 5);

    let minimized = minimize_coordination_pressure_replay(&plan);
    assert_eq!(minimized.stimuli.len(), 1);
    assert_eq!(minimized.log.minimization_steps, 6);
    assert_eq!(
        minimized.log.first_failure_or_refusal.as_deref(),
        Some("dirty_frontier_fail_closed")
    );
}

#[test]
fn coordination_fixture_refuses_missing_scenario_dimensions() {
    let root = temp_root("coordination-refused");
    let out = run_workload_script(&[
        "--synthesize-coordination-pack".into(),
        "--coordination-fixture-id".into(),
        "refused-missing-scenario-dimensions".into(),
        "--output-root".into(),
        root.to_string_lossy().into_owned(),
    ]);
    assert!(
        !out.status.success(),
        "missing dimensions fixture must fail closed"
    );

    let run_dir = root
        .join("coordination-expansion")
        .join("coordination-runtime-fixture-missing-dimensions");
    let report: Value = serde_json::from_str(
        &std::fs::read_to_string(run_dir.join("coordination-workload-synthesis-report.json"))
            .expect("read refused report"),
    )
    .expect("parse refused report");
    let pack: Value = serde_json::from_str(
        &std::fs::read_to_string(run_dir.join("coordination-workload-expansion-pack.json"))
            .expect("read refused pack"),
    )
    .expect("parse refused pack");

    assert_eq!(report["status"], "refused");
    assert!(
        report["first_failure_line"]
            .as_str()
            .unwrap_or_default()
            .contains("missing_scenario_dimensions")
    );
    assert_eq!(
        report["missing_scenario_families"]
            .as_array()
            .expect("missing families")
            .len(),
        6
    );
    assert_eq!(
        pack["refused_bundles"][0]["refusal_reason"],
        "missing_scenario_dimensions"
    );
}
