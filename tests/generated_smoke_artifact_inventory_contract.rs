//! Contract tests for generated swarm-perf smoke artifact ownership.

#![allow(missing_docs)]

use serde_json::Value;
use std::collections::BTreeSet;
use std::path::PathBuf;

const ARTIFACT_PATH: &str = "artifacts/generated_smoke_artifact_inventory_v1.json";
const GITIGNORE_PATH: &str = ".gitignore";
const RUNNER_PATH: &str = "scripts/run_generated_smoke_artifact_inventory_smoke.sh";
const ROOT_SMOKE_OUTPUT_DIRS: &[&str] = &[
    ".adaptive-batch-sizing-smoke-artifacts",
    ".blocking-pool-affinity-smoke-artifacts",
    ".capacity-envelope-planner-smoke-artifacts",
    ".cohort-admission-steering-smoke-artifacts",
    ".compile-frontier-movement-smoke-artifacts",
    ".decision-plane-validation-smoke-artifacts",
    ".governor-state-snapshot-smoke-artifacts",
    ".host-profile-planner-smoke-artifacts",
    ".hot-cold-arena-tiers-smoke-artifacts",
    ".jetstream-publish-backpressure-smoke-artifacts",
    ".massive-swarm-signoff-smoke-artifacts",
    ".numa-arena-locality-smoke-artifacts",
    ".otlp-audit-inventory-smoke-artifacts",
    ".otlp-brownout-shedding-smoke-artifacts",
    ".overload-brownout-smoke-artifacts",
    ".read-biased-region-snapshot-smoke-artifacts",
    ".resource-monitor-platform-gap-smoke-artifacts",
    ".runtime-capacity-hints-smoke-artifacts",
    ".signed-profile-bundle-smoke-artifacts",
    ".tail-risk-admission-smoke-artifacts",
    ".task-record-pool-smoke-artifacts",
    ".trace-storage-profile-smoke-artifacts",
    "topology-smoke-out",
];

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn read_workspace_file(path: &str) -> String {
    std::fs::read_to_string(repo_root().join(path))
        .unwrap_or_else(|error| panic!("failed to read {path}: {error}"))
}

fn load_artifact() -> Value {
    serde_json::from_str(&read_workspace_file(ARTIFACT_PATH))
        .expect("generated smoke artifact inventory must parse as JSON")
}

fn gitignore_patterns() -> BTreeSet<String> {
    read_workspace_file(GITIGNORE_PATH)
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(ToOwned::to_owned)
        .collect()
}

fn ignored_root_pattern(root: &str) -> String {
    format!("/{root}/")
}

fn validate_inventory(artifact: &Value) -> Result<(), String> {
    let required_top_level = [
        "schema_version",
        "bead_id",
        "policy",
        "canonical_guidance",
        "local_host_snapshot",
        "clusters",
        "smoke_scenarios",
    ];
    for field in required_top_level {
        if artifact.get(field).is_none() {
            return Err(format!("missing top-level field {field}"));
        }
    }

    if artifact["schema_version"] != "generated-smoke-artifact-inventory-v1" {
        return Err("unexpected schema_version".to_string());
    }
    if artifact["bead_id"] != "asupersync-beih6k" {
        return Err("inventory must be owned by asupersync-beih6k".to_string());
    }
    if artifact["policy"]["no_deletion_confirmation"].as_bool() != Some(true) {
        return Err("inventory must explicitly confirm no deletion".to_string());
    }
    let signoff_rule = artifact["policy"]["final_signoff_rule"]
        .as_str()
        .ok_or_else(|| "final_signoff_rule must be string".to_string())?;
    if !signoff_rule.contains("fail_closed") {
        return Err("final signoff rule must fail closed".to_string());
    }

    let clusters = artifact["clusters"]
        .as_array()
        .ok_or_else(|| "clusters must be array".to_string())?;
    let snapshot = &artifact["local_host_snapshot"];
    if clusters.len() as u64 != snapshot["expected_cluster_count"].as_u64().unwrap_or(0) {
        return Err("cluster count does not match local host snapshot".to_string());
    }

    let mut cluster_ids = BTreeSet::new();
    let mut output_roots = BTreeSet::new();
    let mut owner_beads = BTreeSet::new();
    let mut file_count = 0_u64;
    let mut total_bytes = 0_u64;
    let mut fail_closed_count = 0_u64;
    let mut no_deletion_count = 0_u64;

    for cluster in clusters {
        let cluster_id = cluster["cluster_id"]
            .as_str()
            .ok_or_else(|| "cluster_id must be string".to_string())?;
        if !cluster_ids.insert(cluster_id.to_string()) {
            return Err(format!("duplicate cluster_id {cluster_id}"));
        }

        let output_root = cluster["output_root"]
            .as_str()
            .ok_or_else(|| "output_root must be string".to_string())?;
        output_roots.insert(output_root.to_string());

        let owners = cluster["owner_beads"]
            .as_array()
            .ok_or_else(|| "owner_beads must be array".to_string())?;
        if owners.is_empty() {
            return Err(format!("cluster {cluster_id} has no owner bead"));
        }
        for owner in owners {
            owner_beads.insert(
                owner
                    .as_str()
                    .ok_or_else(|| "owner bead IDs must be strings".to_string())?
                    .to_string(),
            );
        }

        if cluster["runner_path"].as_str().is_none_or(str::is_empty) {
            return Err(format!("cluster {cluster_id} has no runner path"));
        }
        let runner_path = cluster["runner_path"]
            .as_str()
            .ok_or_else(|| "runner_path must be string".to_string())?;
        if cluster["scenario_ids"].as_array().map_or(0, Vec::len) == 0 {
            return Err(format!("cluster {cluster_id} has no scenarios"));
        }
        for scenario in cluster["scenario_ids"]
            .as_array()
            .ok_or_else(|| "scenario_ids must be array".to_string())?
        {
            if scenario.as_str().is_none_or(str::is_empty) {
                return Err(format!("cluster {cluster_id} has an empty scenario id"));
            }
        }
        if cluster["reproduction_command"]
            .as_str()
            .is_none_or(str::is_empty)
        {
            return Err(format!("cluster {cluster_id} has no reproduction command"));
        }
        let reproduction_command = cluster["reproduction_command"]
            .as_str()
            .ok_or_else(|| "reproduction_command must be string".to_string())?;
        if !reproduction_command.contains(runner_path) {
            return Err(format!(
                "cluster {cluster_id} reproduction command must invoke its runner"
            ));
        }
        if cluster["report_glob"].as_str().is_none_or(str::is_empty) {
            return Err(format!("cluster {cluster_id} has no report glob"));
        }
        if cluster["retention_decision"]
            .as_str()
            .is_none_or(str::is_empty)
        {
            return Err(format!("cluster {cluster_id} has no retention decision"));
        }
        if cluster["stable_file_list_sha256"]
            .as_str()
            .is_none_or(|hash| hash.len() != 64)
        {
            return Err(format!("cluster {cluster_id} lacks stable file-list hash"));
        }
        if cluster["checksum_manifest_sha256"]
            .as_str()
            .is_none_or(|hash| hash.len() != 64)
        {
            return Err(format!("cluster {cluster_id} lacks checksum manifest hash"));
        }
        if cluster["no_deletion_confirmation"].as_bool() != Some(true) {
            return Err(format!(
                "cluster {cluster_id} lacks no-deletion confirmation"
            ));
        }

        let signoff_status = cluster["signoff_status"]
            .as_str()
            .ok_or_else(|| "signoff_status must be string".to_string())?;
        if signoff_status.starts_with("fail_closed") {
            fail_closed_count += 1;
        }
        if cluster["owner_status"].as_str() == Some("open")
            && !signoff_status.starts_with("fail_closed")
        {
            return Err(format!(
                "open owner cluster {cluster_id} must fail closed until owner closeout"
            ));
        }
        no_deletion_count += 1;
        file_count += cluster["expected_file_count"].as_u64().unwrap_or(0);
        total_bytes += cluster["expected_total_bytes"].as_u64().unwrap_or(0);
    }

    if file_count != snapshot["expected_file_count"].as_u64().unwrap_or(0) {
        return Err("file count sum does not match snapshot".to_string());
    }
    if total_bytes != snapshot["expected_total_bytes"].as_u64().unwrap_or(0) {
        return Err("byte count sum does not match snapshot".to_string());
    }

    let scenario = artifact["smoke_scenarios"][0].clone();
    let expected = &scenario["expected_counts"];
    if fail_closed_count != expected["fail_closed_cluster_count"].as_u64().unwrap_or(0) {
        return Err("fail-closed cluster count does not match scenario".to_string());
    }
    if no_deletion_count
        != expected["no_deletion_confirmation_count"]
            .as_u64()
            .unwrap_or(0)
    {
        return Err("no-deletion count does not match scenario".to_string());
    }
    if owner_beads.len() < 8 {
        return Err("inventory should map clusters to the swarm-perf owner beads".to_string());
    }

    Ok(())
}

#[test]
fn artifact_and_runner_exist() {
    assert!(
        repo_root().join(ARTIFACT_PATH).exists(),
        "generated smoke artifact inventory must exist"
    );
    assert!(
        repo_root().join(RUNNER_PATH).exists(),
        "generated smoke artifact inventory runner must exist"
    );
}

#[test]
fn inventory_schema_and_counts_are_valid() {
    let artifact = load_artifact();
    validate_inventory(&artifact).expect("inventory contract should be complete");
}

#[test]
fn root_smoke_output_dirs_are_gitignored() {
    let patterns = gitignore_patterns();
    for root in ROOT_SMOKE_OUTPUT_DIRS {
        let pattern = ignored_root_pattern(root);
        assert!(
            patterns.contains(&pattern),
            "root smoke artifact dir {root} must be ignored with {pattern}"
        );
    }

    let artifact = load_artifact();
    let clusters = artifact["clusters"]
        .as_array()
        .expect("clusters must be an array");
    for cluster in clusters {
        let output_root = cluster["output_root"]
            .as_str()
            .expect("output_root must be a string");
        if output_root.starts_with("target/") {
            continue;
        }

        let pattern = ignored_root_pattern(output_root);
        assert!(
            patterns.contains(&pattern),
            "inventoried smoke output_root {output_root} must be ignored with {pattern}"
        );
    }
}

#[test]
fn inventory_rejects_missing_fail_closed_policy() {
    let mut artifact = load_artifact();
    artifact["policy"]["final_signoff_rule"] = Value::from("trust_everything");
    assert!(
        validate_inventory(&artifact)
            .expect_err("non-fail-closed policy should be rejected")
            .contains("fail closed")
    );
}

#[test]
fn inventory_rejects_cluster_without_owner() {
    let mut artifact = load_artifact();
    artifact["clusters"][0]["owner_beads"] = Value::Array(Vec::new());
    assert!(
        validate_inventory(&artifact)
            .expect_err("ownerless cluster should be rejected")
            .contains("owner bead")
    );
}

#[test]
fn inventory_rejects_missing_checksum_hash() {
    let mut artifact = load_artifact();
    artifact["clusters"][0]["checksum_manifest_sha256"] = Value::from("");
    assert!(
        validate_inventory(&artifact)
            .expect_err("missing checksum hash should be rejected")
            .contains("checksum")
    );
}

#[test]
fn inventory_covers_live_generated_roots_from_dirty_tree_audit() {
    let artifact = load_artifact();
    let roots: BTreeSet<_> = artifact["clusters"]
        .as_array()
        .expect("clusters array")
        .iter()
        .map(|cluster| cluster["output_root"].as_str().expect("output root"))
        .collect();
    for root in [
        ".blocking-pool-affinity-smoke-artifacts",
        ".cohort-admission-steering-smoke-artifacts",
        ".decision-plane-validation-smoke-artifacts",
        ".governor-state-snapshot-smoke-artifacts",
        ".overload-brownout-smoke-artifacts",
        ".read-biased-region-snapshot-smoke-artifacts",
        ".tail-risk-admission-smoke-artifacts",
        ".trace-storage-profile-smoke-artifacts",
        "topology-smoke-out",
    ] {
        assert!(roots.contains(root), "inventory must cover {root}");
    }
}

#[test]
fn gitignore_marks_generated_roots_as_local_evidence() {
    let artifact = load_artifact();
    let gitignore = read_workspace_file(".gitignore");
    for cluster in artifact["clusters"].as_array().expect("clusters array") {
        let root = cluster["output_root"].as_str().expect("output_root string");
        assert!(
            gitignore.contains(&format!("/{root}/")),
            ".gitignore must ignore generated output root {root}"
        );
    }
    assert!(
        gitignore.contains("!artifacts/generated_smoke_artifact_inventory_v1.json"),
        ".gitignore must allow the versioned inventory artifact"
    );
}

#[test]
fn required_log_fields_cover_operator_signoff() {
    let artifact = load_artifact();
    let fields: BTreeSet<_> = artifact["smoke_scenarios"][0]["required_log_fields"]
        .as_array()
        .expect("required log fields")
        .iter()
        .map(|value| value.as_str().expect("field string"))
        .collect();
    for required in [
        "scenario_id",
        "contract_version",
        "source_repo_hash",
        "git_branch",
        "git_upstream",
        "output_root",
        "run_dir",
        "inventory_artifact_path",
        "present_cluster_count",
        "missing_cluster_count",
        "checksum_match_count",
        "owner_bead_count",
        "fail_closed_cluster_count",
        "no_deletion_confirmation_count",
        "retention_decision",
        "fallback_decision",
        "rch_queue_state",
        "cluster_report_path",
        "bundle_manifest_path",
        "run_report_path",
        "run_log_path",
        "generated_artifact_paths",
        "final_verdict",
    ] {
        assert!(
            fields.contains(required),
            "missing required operator log field {required}"
        );
    }
}

#[test]
fn runner_supports_modes_and_logs_required_fields() {
    let artifact = load_artifact();
    let runner = read_workspace_file(RUNNER_PATH);
    for flag in [
        "--list",
        "--dry-run",
        "--execute",
        "--output-root",
        "--scenario",
    ] {
        assert!(runner.contains(flag), "runner must support {flag}");
    }

    for field in artifact["smoke_scenarios"][0]["required_log_fields"]
        .as_array()
        .expect("required log fields")
    {
        let field = field.as_str().expect("required field string");
        let log_assignment = format!("echo \"{field}=");
        let json_key = format!("\"{field}\":");
        assert!(
            runner.contains(&log_assignment) || runner.contains(&json_key),
            "runner must emit operator field {field}"
        );
    }
}
