#![allow(missing_docs)]

use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

const ARTIFACT_PATH: &str = "artifacts/fourth_wave_swarm_governor_benchmark_contract_v1.json";
const SCHEMA_VERSION: &str = "fourth-wave-swarm-governor-benchmark-contract-v1";

fn repo_path(relative: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(relative)
}

fn read_text(relative: &str) -> String {
    std::fs::read_to_string(repo_path(relative))
        .unwrap_or_else(|error| panic!("read {relative}: {error}"))
}

fn artifact() -> Value {
    serde_json::from_str(&read_text(ARTIFACT_PATH))
        .unwrap_or_else(|error| panic!("parse {ARTIFACT_PATH}: {error}"))
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

fn bool_field(value: &Value, key: &str) -> bool {
    value
        .get(key)
        .and_then(Value::as_bool)
        .unwrap_or_else(|| panic!("{key} must be a bool"))
}

fn u64_field(value: &Value, key: &str) -> u64 {
    value
        .get(key)
        .and_then(Value::as_u64)
        .unwrap_or_else(|| panic!("{key} must be an unsigned integer"))
}

fn string_set(value: &Value, key: &str) -> BTreeSet<String> {
    array(value, key)
        .iter()
        .map(|entry| {
            entry
                .as_str()
                .unwrap_or_else(|| panic!("{key} entries must be strings"))
                .to_string()
        })
        .collect()
}

fn scenarios(artifact: &Value) -> BTreeMap<String, &Value> {
    array(artifact, "scenario_catalog")
        .iter()
        .map(|row| (string(row, "scenario_id").to_string(), row))
        .collect()
}

fn scenario_mode_set(row: &Value) -> BTreeSet<String> {
    array(row, "measurement_modes")
        .iter()
        .map(|mode| string(mode, "mode").to_string())
        .collect()
}

fn assert_remote_required_command(command: &str, field: &str, scenario_id: &str) {
    assert!(
        command.starts_with("RCH_REQUIRE_REMOTE=1 rch exec -- env "),
        "{scenario_id}: {field} must be remote-required RCH"
    );
    assert!(
        command.contains("CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_fourth_wave_"),
        "{scenario_id}: {field} must isolate a fourth-wave target dir"
    );
    assert!(
        command.contains(" cargo "),
        "{scenario_id}: {field} must run the Cargo proof/benchmark through RCH"
    );
}

#[test]
fn artifact_declares_source_boundary_and_no_claims() {
    let artifact = artifact();
    assert_eq!(
        artifact.get("schema_version").and_then(Value::as_str),
        Some(SCHEMA_VERSION)
    );
    assert_eq!(
        artifact.get("bead_id").and_then(Value::as_str),
        Some("asupersync-86fe9v.7")
    );

    for path in object(&artifact, "source_of_truth").values() {
        let path = path.as_str().expect("source path string");
        assert!(repo_path(path).exists(), "source path must exist: {path}");
    }

    let host = artifact.get("host_profile").expect("host_profile");
    assert_eq!(u64_field(host, "cpu_cores"), 64);
    assert_eq!(u64_field(host, "memory_gib"), 256);
    assert!(bool_field(host, "same_host_required"));
    assert!(bool_field(host, "remote_required"));
    assert!(!bool_field(host, "local_fallback_allowed"));
    assert!(bool_field(host, "frame_pointers_required"));

    let boundary = artifact.get("proof_boundary").expect("proof_boundary");
    for field in [
        "contract_receipts_are_fresh_benchmarks",
        "proves_real_host_improvement",
        "proves_no_regression",
        "proves_scheduler_performance",
        "local_cargo_fallback_allowed",
    ] {
        assert!(!bool_field(boundary, field), "{field} must remain false");
    }
    assert!(bool_field(boundary, "requires_rch_refresh_for_claims"));
    assert!(bool_field(
        boundary,
        "flamegraph_attribution_is_expected_target_map"
    ));

    let report = artifact.get("no_claim_report").expect("no_claim_report");
    assert_eq!(
        report.get("status").and_then(Value::as_str),
        Some("no-improvement-claim")
    );
    let blocked = string_set(report, "blocked_claims");
    assert!(blocked.contains("fourth-wave governor improves p95 latency"));
    assert!(blocked.contains("fourth-wave governor is production-on-by-default"));
}

#[test]
fn scenarios_cover_required_workloads_and_modes() {
    let artifact = artifact();
    let expected_scenarios = string_set(&artifact, "required_scenario_ids");
    let rows = scenarios(&artifact);
    assert_eq!(
        rows.keys().cloned().collect::<BTreeSet<_>>(),
        expected_scenarios
    );
    assert_eq!(rows.len(), 5, "contract must cover the five .7 workloads");

    let required_modes = string_set(&artifact, "required_modes");
    assert_eq!(
        required_modes,
        [
            "observe_only_baseline",
            "advisory_decision_output",
            "opt_in_bridge_behavior"
        ]
        .into_iter()
        .map(String::from)
        .collect()
    );

    for (scenario_id, row) in rows {
        assert_eq!(
            scenario_mode_set(row),
            required_modes,
            "{scenario_id}: mode coverage"
        );
        let envelope = row.get("worker_envelope").expect("worker_envelope");
        assert!(u64_field(envelope, "worker_count") >= 48);
        assert!(u64_field(envelope, "agent_count") >= 48);
        assert!(u64_field(envelope, "memory_ceiling_gib") >= 128);

        for source_ref in array(row, "source_refs") {
            let source_ref = source_ref.as_str().expect("source_ref string");
            assert!(
                repo_path(source_ref).exists(),
                "{scenario_id}: source_ref must exist: {source_ref}"
            );
        }
    }
}

#[test]
fn refresh_commands_are_remote_required_and_target_isolated() {
    let artifact = artifact();
    for row in array(&artifact, "scenario_catalog") {
        let scenario_id = string(row, "scenario_id");
        assert_remote_required_command(
            string(row, "benchmark_refresh_command"),
            "benchmark_refresh_command",
            scenario_id,
        );
        assert_remote_required_command(
            string(row, "contract_refresh_command"),
            "contract_refresh_command",
            scenario_id,
        );
        assert!(
            string(row, "contract_refresh_command").contains(
                "cargo test -p asupersync --test fourth_wave_swarm_governor_benchmark_contract"
            ),
            "{scenario_id}: contract refresh must prove this contract"
        );
    }
}

#[test]
fn metric_and_log_contract_requires_tail_memory_queue_and_drain_fields() {
    let artifact = artifact();
    let required_metrics = string_set(&artifact, "required_metric_fields");
    let expected_metrics = [
        "p50_us",
        "p95_us",
        "p99_us",
        "throughput_ops_per_sec",
        "queue_delay_p95_us",
        "cancellation_drain_p95_us",
        "peak_rss_mb",
        "fairness_yield_count",
    ]
    .into_iter()
    .map(String::from)
    .collect::<BTreeSet<_>>();
    assert_eq!(required_metrics, expected_metrics);

    let required_logs = string_set(&artifact, "required_log_fields");
    for field in [
        "scenario_id",
        "run_id",
        "git_sha",
        "host_profile_id",
        "worker_count",
        "command",
        "target_dir",
        "flamegraph_artifact_path",
        "claim_status",
    ] {
        assert!(required_logs.contains(field), "required log field {field}");
    }

    for row in array(&artifact, "scenario_catalog") {
        let scenario_id = string(row, "scenario_id");
        for mode in array(row, "measurement_modes") {
            assert_eq!(
                string_set(mode, "metric_fields"),
                required_metrics,
                "{scenario_id}/{} metric fields",
                string(mode, "mode")
            );
            assert!(!bool_field(mode, "fresh_rch_benchmark"));
            assert_eq!(string(mode, "claim_status"), "refresh_required");
        }
    }
}

#[test]
fn flamegraph_attribution_is_ranked_and_source_backed() {
    let artifact = artifact();
    for row in array(&artifact, "scenario_catalog") {
        let scenario_id = string(row, "scenario_id");
        let flamegraph = row
            .get("flamegraph_attribution")
            .unwrap_or_else(|| panic!("{scenario_id}: flamegraph_attribution"));
        let artifact_path = string(flamegraph, "expected_artifact_path");
        assert!(
            artifact_path.starts_with("artifacts/perf/fourth_wave/"),
            "{scenario_id}: flamegraph artifact must stay under artifacts/perf/fourth_wave"
        );
        assert!(
            artifact_path.ends_with("/flamegraph.svg"),
            "{scenario_id}: expected flamegraph path must end with flamegraph.svg"
        );
        assert!(bool_field(flamegraph, "refresh_requires_frame_pointers"));

        let targets = array(flamegraph, "ranked_targets");
        assert!(
            targets.len() >= 3,
            "{scenario_id}: at least three attribution targets"
        );
        for (index, target) in targets.iter().enumerate() {
            assert_eq!(
                target.get("rank").and_then(Value::as_u64),
                Some((index + 1) as u64),
                "{scenario_id}: ranks must be contiguous"
            );
            let path = string(target, "path");
            assert!(
                repo_path(path).exists(),
                "{scenario_id}: target path must exist: {path}"
            );
            string(target, "symbol");
            string(target, "expected_pressure");
        }
    }
}
