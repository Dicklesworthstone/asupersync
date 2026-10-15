#![allow(missing_docs)]

use serde_json::Value;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const ARTIFACT_PATH: &str = "artifacts/large_host_topology_corpus_v1.json";
const DOC_PATH: &str = "docs/large_host_topology_corpus.md";
const E2E_SCRIPT_PATH: &str = "scripts/run_large_host_topology_corpus_e2e.sh";
const FIXTURE_ROOT: &str = "tests/fixtures/large_host_topology_corpus";
const GENERATED_AT: &str = "2026-06-06T04:05:00Z";
const SCRIPT_PATH: &str = "scripts/large_host_topology_corpus.py";

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn repo_path(relative: &str) -> PathBuf {
    repo_root().join(relative)
}

fn read_text(relative: &str) -> String {
    std::fs::read_to_string(repo_path(relative))
        .unwrap_or_else(|error| panic!("read {relative}: {error}"))
}

fn read_json(relative: &str) -> Value {
    serde_json::from_str(&read_text(relative))
        .unwrap_or_else(|error| panic!("parse {relative}: {error}"))
}

fn artifact() -> Value {
    read_json(ARTIFACT_PATH)
}

fn array<'a>(value: &'a Value, key: &str) -> &'a Vec<Value> {
    value
        .get(key)
        .and_then(Value::as_array)
        .unwrap_or_else(|| panic!("{key} must be an array"))
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

fn u64_field(value: &Value, key: &str) -> u64 {
    value
        .get(key)
        .and_then(Value::as_u64)
        .unwrap_or_else(|| panic!("{key} must be a positive integer"))
}

fn bool_member(value: &serde_json::Map<String, Value>, key: &str) -> bool {
    value
        .get(key)
        .and_then(Value::as_bool)
        .unwrap_or_else(|| panic!("{key} must be a bool"))
}

fn string_set(value: &Value, key: &str) -> BTreeSet<String> {
    array(value, key)
        .iter()
        .map(|item| {
            item.as_str()
                .unwrap_or_else(|| panic!("{key} entries must be strings"))
                .to_string()
        })
        .collect()
}

fn find_profile<'a>(artifact: &'a Value, profile_id: &str) -> &'a Value {
    array(artifact, "profile_catalog")
        .iter()
        .find(|row| row.get("profile_id").and_then(Value::as_str) == Some(profile_id))
        .unwrap_or_else(|| panic!("profile missing: {profile_id}"))
}

fn run_helper_with_fixture(fixture: &Path, output: &str) -> Output {
    Command::new("python3")
        .current_dir(repo_root())
        .arg(repo_path(SCRIPT_PATH))
        .arg("--fixture")
        .arg(fixture)
        .arg("--repo-path")
        .arg(repo_root())
        .arg("--generated-at")
        .arg(GENERATED_AT)
        .arg("--output")
        .arg(output)
        .output()
        .expect("run topology corpus helper")
}

fn run_helper_json(relative_fixture: &str) -> Value {
    let output = run_helper_with_fixture(&repo_path(relative_fixture), "json");
    assert!(
        output.status.success(),
        "helper failed: {}\nstdout:\n{}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("helper stdout must be JSON")
}

fn assert_hash(value: &str, field: &str) {
    assert!(
        value.starts_with("sha256:") && value.len() == "sha256:".len() + 64,
        "{field} must be sha256:<64 lowercase hex>, got {value}"
    );
    assert!(
        value["sha256:".len()..]
            .chars()
            .all(|ch| ch.is_ascii_hexdigit() && !ch.is_ascii_uppercase()),
        "{field} must use lowercase hex"
    );
}

#[test]
fn artifact_declares_schema_sources_and_profile_catalog() {
    let artifact = artifact();
    assert_eq!(
        artifact.get("schema_version").and_then(Value::as_str),
        Some("large-host-topology-corpus-v1")
    );
    assert_eq!(
        artifact.get("bead_id").and_then(Value::as_str),
        Some("asupersync-ol11aa.1")
    );

    for path in object(&artifact, "source_of_truth").values() {
        let path = path.as_str().expect("source path string");
        assert!(repo_path(path).exists(), "source path must exist: {path}");
    }

    let expected = [
        "single-socket-64c-256g",
        "dual-socket-64c-256g-numa",
        "high-memory-96c-512g",
        "cgroup-limited-32c-96g",
        "memory-pressure-degraded-64c",
        "remote-worker-queue-contention-64c-256g",
    ]
    .into_iter()
    .map(String::from)
    .collect::<BTreeSet<_>>();
    let actual = array(&artifact, "profile_catalog")
        .iter()
        .map(|row| string(row, "profile_id").to_string())
        .collect::<BTreeSet<_>>();
    assert_eq!(actual, expected);
    assert_eq!(string_set(&artifact, "required_profile_ids"), expected);
}

#[test]
fn profile_rows_have_topology_memory_cgroup_and_fallback_boundaries() {
    let artifact = artifact();
    for row in array(&artifact, "profile_catalog") {
        let profile_id = string(row, "profile_id");
        for field in array(&artifact, "required_profile_fields") {
            let field = field.as_str().expect("required field string");
            assert!(
                row.get(field).is_some(),
                "{profile_id}: missing required field {field}"
            );
        }

        let command = string(row, "rch_refresh_command");
        assert!(
            command.starts_with("RCH_REQUIRE_REMOTE=1 rch exec -- env "),
            "{profile_id}: refresh command must be remote-required RCH"
        );
        assert!(
            command.contains("CARGO_TARGET_DIR="),
            "{profile_id}: refresh command must isolate CARGO_TARGET_DIR"
        );

        let topology = object(row, "topology");
        let physical_cores = topology["physical_cores"].as_u64().expect("physical cores");
        let hardware_threads = topology["hardware_threads"]
            .as_u64()
            .expect("hardware threads");
        assert!(physical_cores >= 32, "{profile_id}: physical cores");
        assert!(
            hardware_threads >= physical_cores,
            "{profile_id}: hardware threads"
        );
        assert!(topology["socket_count"].as_u64().unwrap_or(0) >= 1);
        let numa_nodes = topology["numa_nodes"].as_u64().expect("numa nodes");
        assert!(numa_nodes >= 1, "{profile_id}: numa nodes");
        let cache_domains = array(row.get("topology").expect("topology"), "cache_domains");
        assert!(
            !cache_domains.is_empty(),
            "{profile_id}: cache domains must be nonempty"
        );
        for domain in cache_domains {
            string(domain, "domain_id");
            string(domain, "core_range");
            assert!(
                u64_field(domain, "shared_l3_mib") > 0,
                "{profile_id}: shared_l3_mib"
            );
        }

        let memory = object(row, "memory");
        assert!(u64_field(row.get("memory").expect("memory"), "total_gib") >= 96);
        assert!(
            u64_field(
                row.get("memory").expect("memory"),
                "admission_memory_ceiling_gib"
            ) > 0
        );
        assert_eq!(
            memory
                .get("per_numa_node_gib")
                .and_then(Value::as_array)
                .expect("per_numa_node_gib")
                .len(),
            numa_nodes as usize,
            "{profile_id}: per-NUMA memory rows"
        );

        let cgroup = object(row, "cgroup");
        assert!(
            !bool_member(cgroup, "detected_from_live_host"),
            "{profile_id}: deterministic corpus must not claim live host detection"
        );
        assert!(u64_field(row.get("cgroup").expect("cgroup"), "cpuset_effective_cores") > 0);
        assert!(u64_field(row.get("cgroup").expect("cgroup"), "memory_max_gib") > 0);

        let slots = object(row, "rch_slot_model");
        assert!(
            slots["recommended_slots"].as_u64().unwrap_or(0) > 0,
            "{profile_id}: recommended_slots"
        );
        assert!(
            slots["max_parallel_heavy_lanes"].as_u64().unwrap_or(0) > 0,
            "{profile_id}: max_parallel_heavy_lanes"
        );

        let fallback = object(row, "fallback_policy");
        string(
            row.get("fallback_policy").expect("fallback_policy"),
            "missing_topology_action",
        );
        string(
            row.get("fallback_policy").expect("fallback_policy"),
            "safe_default_profile",
        );
        assert!(
            !array(
                row.get("fallback_policy").expect("fallback_policy"),
                "reason_codes"
            )
            .is_empty(),
            "{profile_id}: fallback reason codes"
        );

        let proof_boundary = object(row, "proof_boundary");
        assert!(!bool_member(
            proof_boundary,
            "corpus_is_live_host_measurement"
        ));
        assert!(!bool_member(proof_boundary, "corpus_is_fresh_benchmark"));
        assert!(!bool_member(proof_boundary, "proves_real_host_throughput"));
        assert!(bool_member(proof_boundary, "operator_guidance_only"));

        assert!(
            !array(row, "contention_domains").is_empty(),
            "{profile_id}: contention domains"
        );
        for source_ref in array(row, "source_refs") {
            let source_ref = source_ref.as_str().expect("source ref string");
            assert!(
                repo_path(source_ref).exists(),
                "{profile_id}: source ref missing: {source_ref}"
            );
        }

        assert!(
            !fallback.is_empty(),
            "{profile_id}: fallback policy must be present"
        );
    }
}

#[test]
fn single_socket_profile_declares_flat_topology() {
    let artifact = artifact();
    let row = find_profile(&artifact, "single-socket-64c-256g");
    let topology = object(row, "topology");
    assert_eq!(topology["socket_count"].as_u64(), Some(1));
    assert_eq!(topology["numa_nodes"].as_u64(), Some(1));
    assert_eq!(topology["physical_cores"].as_u64(), Some(64));
    assert_eq!(
        u64_field(row.get("memory").expect("memory"), "total_gib"),
        256
    );
}

#[test]
fn dual_socket_profile_declares_numa_domains() {
    let artifact = artifact();
    let row = find_profile(&artifact, "dual-socket-64c-256g-numa");
    let topology = object(row, "topology");
    assert_eq!(topology["socket_count"].as_u64(), Some(2));
    assert_eq!(topology["numa_nodes"].as_u64(), Some(2));
    assert_eq!(
        array(row.get("topology").expect("topology"), "cache_domains").len(),
        2
    );
    assert_eq!(
        array(row.get("memory").expect("memory"), "per_numa_node_gib")
            .iter()
            .map(Value::as_u64)
            .collect::<Vec<_>>(),
        vec![Some(128), Some(128)]
    );
}

#[test]
fn high_memory_profile_declares_large_memory_ceiling() {
    let artifact = artifact();
    let row = find_profile(&artifact, "high-memory-96c-512g");
    assert_eq!(
        u64_field(row.get("topology").expect("topology"), "physical_cores"),
        96
    );
    assert_eq!(
        u64_field(row.get("memory").expect("memory"), "total_gib"),
        512
    );
    assert!(
        u64_field(
            row.get("memory").expect("memory"),
            "admission_memory_ceiling_gib"
        ) >= 384
    );
    assert_eq!(
        array(row.get("memory").expect("memory"), "per_numa_node_gib").len(),
        4
    );
}

#[test]
fn cgroup_limited_profile_declares_effective_limits() {
    let artifact = artifact();
    let row = find_profile(&artifact, "cgroup-limited-32c-96g");
    let cgroup = object(row, "cgroup");
    assert_eq!(cgroup["cpuset_effective_cores"].as_u64(), Some(32));
    assert_eq!(cgroup["memory_max_gib"].as_u64(), Some(96));
    assert_eq!(
        object(row, "rch_slot_model")["max_parallel_heavy_lanes"].as_u64(),
        Some(1)
    );
}

#[test]
fn degraded_profile_declares_safe_fallback() {
    let artifact = artifact();
    let row = find_profile(&artifact, "memory-pressure-degraded-64c");
    assert_eq!(
        string(row.get("memory").expect("memory"), "memory_pressure_state"),
        "degraded"
    );
    assert_eq!(
        object(row, "rch_slot_model")["max_parallel_heavy_lanes"].as_u64(),
        Some(1)
    );
    assert!(
        array(
            row.get("fallback_policy").expect("fallback_policy"),
            "reason_codes",
        )
        .iter()
        .map(Value::as_str)
        .any(|reason_code| reason_code == Some("memory-pressure"))
    );
}

#[test]
fn remote_worker_contention_profile_declares_queue_policy() {
    let artifact = artifact();
    let row = find_profile(&artifact, "remote-worker-queue-contention-64c-256g");
    assert_eq!(
        string(row, "profile_family"),
        "remote_worker_queue_contention"
    );
    assert_eq!(
        object(row, "rch_slot_model")["max_parallel_heavy_lanes"].as_u64(),
        Some(1)
    );
    assert!(
        array(
            row.get("fallback_policy").expect("fallback_policy"),
            "reason_codes",
        )
        .iter()
        .map(Value::as_str)
        .any(|reason_code| reason_code == Some("zero-test-evidence-not-proof"))
    );
}

#[test]
fn proof_boundary_and_docs_preserve_non_claims() {
    let artifact = artifact();
    let boundary = object(&artifact, "proof_boundary");
    assert!(!bool_member(boundary, "corpus_is_live_host_measurement"));
    assert!(!bool_member(boundary, "corpus_is_fresh_benchmark"));
    assert!(!bool_member(boundary, "proves_real_host_throughput"));
    assert!(!bool_member(boundary, "proves_rch_fleet_availability"));
    assert!(!bool_member(boundary, "local_cargo_fallback_allowed"));
    assert!(bool_member(boundary, "requires_rch_for_refresh_commands"));

    let docs = read_text(DOC_PATH);
    for marker in [
        "large-host-topology-corpus-v1",
        "not live host measurement",
        "not a benchmark report",
        "RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_TARGET_DIR=",
        "Local Cargo fallback is not admissible",
        "single-socket-64c-256g",
        "dual-socket-64c-256g-numa",
        "high-memory-96c-512g",
        "cgroup-limited-32c-96g",
        "memory-pressure-degraded-64c",
        "remote-worker-queue-contention-64c-256g",
    ] {
        assert!(docs.contains(marker), "docs missing marker {marker}");
    }
}

#[test]
fn helper_emits_stable_json_and_markdown_from_artifact() {
    let report = run_helper_json(ARTIFACT_PATH);
    assert_eq!(
        report.get("schema_version").and_then(Value::as_str),
        Some("large-host-topology-corpus-report-v1")
    );
    assert_eq!(
        report.get("generated_at").and_then(Value::as_str),
        Some(GENERATED_AT)
    );
    assert_eq!(
        report["operator_summary"]["validation_passed"].as_bool(),
        Some(true)
    );
    assert_eq!(
        report["operator_summary"]["profile_count"].as_u64(),
        Some(6)
    );
    assert_eq!(array(&report, "blockers").len(), 0);
    assert_hash(
        report
            .get("source_digest")
            .and_then(Value::as_str)
            .unwrap_or(""),
        "source_digest",
    );

    let output = run_helper_with_fixture(&repo_path(ARTIFACT_PATH), "markdown");
    assert!(output.status.success(), "markdown helper should succeed");
    let markdown = String::from_utf8(output.stdout).expect("markdown utf8");
    assert!(markdown.contains("| single-socket-64c-256g | single_socket_high_core | pass |"));
    assert!(markdown.contains("## Refresh Commands"));
    assert!(markdown.contains("not live host measurement"));
}

#[test]
fn helper_reports_missing_required_fields_without_mutating() {
    let report = run_helper_json(&format!("{FIXTURE_ROOT}/missing_required_field.json"));
    assert_eq!(
        report["operator_summary"]["validation_passed"].as_bool(),
        Some(false)
    );
    let blocker_kinds = array(&report, "blockers")
        .iter()
        .map(|blocker| string(blocker, "kind"))
        .collect::<BTreeSet<_>>();
    assert!(blocker_kinds.contains("missing-required-field"));
    assert!(blocker_kinds.contains("missing-topology"));
    assert!(blocker_kinds.contains("missing-fallback-policy"));

    let forbidden = object(&report, "forbidden_actions");
    for value in forbidden.values() {
        assert_eq!(value.as_bool(), Some(false));
    }
}

#[test]
fn e2e_script_writes_json_markdown_and_detailed_logs() {
    let temp = tempfile::tempdir().expect("tempdir");
    let output = Command::new(repo_path(E2E_SCRIPT_PATH))
        .current_dir(repo_root())
        .arg("--fixture")
        .arg(repo_path(ARTIFACT_PATH))
        .arg("--output-root")
        .arg(temp.path())
        .arg("--run-id")
        .arg("contract-test")
        .arg("--generated-at")
        .arg(GENERATED_AT)
        .output()
        .expect("run topology corpus e2e");
    assert!(
        output.status.success(),
        "e2e failed: {}\nstdout:\n{}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let run_dir = temp.path().join("run_contract-test");
    let json_report = run_dir.join("run_report.json");
    let markdown_report = run_dir.join("run_report.md");
    let run_log = run_dir.join("run.log");
    assert!(json_report.exists(), "json report missing");
    assert!(markdown_report.exists(), "markdown report missing");
    assert!(run_log.exists(), "run log missing");

    let report: Value =
        serde_json::from_str(&std::fs::read_to_string(&json_report).expect("read json e2e report"))
            .expect("parse json e2e report");
    assert_eq!(
        report["operator_summary"]["validation_passed"].as_bool(),
        Some(true)
    );
    let log = std::fs::read_to_string(run_log).expect("read run log");
    assert!(log.contains("profile_id=single-socket-64c-256g"));
    assert!(log.contains("status=pass"));
    assert!(log.contains("first_failure="));
    let stdout = String::from_utf8(output.stdout).expect("stdout utf8");
    assert!(stdout.contains("profile_id=summary"));
}
