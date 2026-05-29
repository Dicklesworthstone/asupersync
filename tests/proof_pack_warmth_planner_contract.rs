//! Contract tests for the dry-run proof-pack warmth planner.

#![allow(missing_docs)]

use serde_json::{Value, json};
use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Output};

const SCRIPT_PATH: &str = "scripts/proof_pack_warmth_planner.py";
const CONTRACT_PATH: &str = "artifacts/proof_pack_cache_key_contract_v1.json";
const GENERATED_AT: &str = "2026-05-29T01:45:00Z";

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn key_input() -> Value {
    json!({
        "cargo_lock_sha256": "aaf0f521d13f2db8cfc04d5a8c10d7c9a4c3f9426bcdd54841c9f4f58f08c2ac",
        "rust_toolchain": {
            "channel": "nightly-2026-05-28",
            "profile": "minimal",
            "components": ["rustfmt", "clippy"],
            "targets": ["x86_64-unknown-linux-gnu"]
        },
        "target_triple": "x86_64-unknown-linux-gnu",
        "workspace_package": "asupersync",
        "features": ["test-internals"],
        "proof_lane_family": "module-microharness",
        "env": {
            "CARGO_BUILD_JOBS": "2",
            "RUSTFLAGS": "-C debuginfo=0"
        },
        "repo": {
            "branch": "main",
            "head_sha": "5cf6642dd2889319a54c53b72d11cb286a6b28ab",
            "ref_kind": "branch"
        }
    })
}

fn base_lane() -> Value {
    json!({
        "lane_id": "module-microharness",
        "target_dir_family": "rch_target_module_microharness_contract",
        "command": "cargo test --test module_microharness_proof_contract",
        "required_worker_capabilities": ["linux", "rust"],
        "cache_key_input": key_input()
    })
}

fn input_with(workers: Value, sampled_at: &str, lanes: Value) -> Value {
    json!({
        "schema_version": "proof-pack-warmth-planner-input-v1",
        "operator": {
            "agent": "MistyCat",
            "target_dir_root": "${TMPDIR:-/tmp}"
        },
        "telemetry": {
            "sampled_at": sampled_at,
            "max_age_seconds": 900,
            "workers": workers
        },
        "proof_lanes": lanes
    })
}

fn run_planner(input: &Value) -> Output {
    let mut file = tempfile::NamedTempFile::new().expect("create planner input");
    file.write_all(
        serde_json::to_string_pretty(input)
            .expect("serialize planner input")
            .as_bytes(),
    )
    .expect("write planner input");

    Command::new("python3")
        .arg(repo_root().join(SCRIPT_PATH))
        .arg("--input")
        .arg(file.path())
        .arg("--contract")
        .arg(repo_root().join(CONTRACT_PATH))
        .arg("--generated-at")
        .arg(GENERATED_AT)
        .arg("--output")
        .arg("json")
        .current_dir(repo_root())
        .output()
        .expect("run proof-pack warmth planner")
}

fn planner_json(input: &Value) -> Value {
    let output = run_planner(input);
    assert!(
        output.status.success(),
        "warmth planner failed: {}\nstdout: {}\nstderr: {}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("planner output must be JSON")
}

fn lane<'a>(receipt: &'a Value, lane_id: &str) -> &'a Value {
    receipt["lanes"]
        .as_array()
        .expect("lanes")
        .iter()
        .find(|row| row["lane_id"].as_str() == Some(lane_id))
        .unwrap_or_else(|| panic!("missing lane {lane_id}"))
}

fn cache_key_for_lane(lane_input: &Value) -> String {
    let receipt = planner_json(&input_with(
        json!([]),
        "2026-05-29T01:44:00Z",
        json!([lane_input.clone()]),
    ));
    lane(&receipt, lane_input["lane_id"].as_str().expect("lane id"))["cache_key"]
        .as_str()
        .expect("cache key")
        .to_string()
}

#[test]
fn script_exists_and_help_is_non_mutating() {
    assert!(
        repo_root().join(SCRIPT_PATH).exists(),
        "planner must exist at {SCRIPT_PATH}"
    );
    let output = Command::new("python3")
        .arg(repo_root().join(SCRIPT_PATH))
        .arg("--help")
        .current_dir(repo_root())
        .output()
        .expect("run helper --help");
    assert!(output.status.success(), "--help should succeed");
}

#[test]
fn warm_worker_is_recommended_with_isolated_rch_command_template() {
    let lane_input = base_lane();
    let cache_key = cache_key_for_lane(&lane_input);
    let receipt = planner_json(&input_with(
        json!([
            {
                "worker_id": "vmi-warm",
                "available_slots": 1,
                "queue_depth": 0,
                "capabilities": ["linux", "rust"],
                "cache_keys": [cache_key]
            },
            {
                "worker_id": "vmi-cold",
                "available_slots": 1,
                "queue_depth": 0,
                "capabilities": ["linux", "rust"],
                "cache_keys": []
            }
        ]),
        "2026-05-29T01:44:30Z",
        json!([lane_input]),
    ));
    let row = lane(&receipt, "module-microharness");

    assert_eq!(
        receipt["schema_version"].as_str(),
        Some("proof-pack-warmth-planner-receipt-v1")
    );
    assert_eq!(
        receipt["contract"]["schema_version"].as_str(),
        Some("proof-pack-cache-key-contract-v1")
    );
    assert_eq!(row["classification"].as_str(), Some("warm"));
    assert_eq!(
        row["recommended_workers"][0]["worker_id"].as_str(),
        Some("vmi-warm")
    );
    let command = row["command_templates"]["actual_proof_command"]
        .as_str()
        .expect("actual proof command");
    assert!(
        command
            .starts_with("rch exec -- env CARGO_TARGET_DIR=\"${TMPDIR:-/tmp}/rch_target_MistyCat_")
    );
    assert!(command.contains("cargo test --test module_microharness_proof_contract"));
    assert_eq!(
        row["command_templates"]["preserves_agent_isolation"].as_bool(),
        Some(true)
    );
    assert_eq!(
        row["command_templates"]["dry_run_only"].as_bool(),
        Some(true)
    );
    assert_eq!(row["cache_warmth_is_authoritative"].as_bool(), Some(false));
}

#[test]
fn cold_available_worker_is_classified_not_warm() {
    let receipt = planner_json(&input_with(
        json!([
            {
                "worker_id": "vmi-cold",
                "available_slots": 2,
                "queue_depth": 0,
                "capabilities": ["linux", "rust"],
                "cache_keys": []
            }
        ]),
        "2026-05-29T01:44:40Z",
        json!([base_lane()]),
    ));
    let row = lane(&receipt, "module-microharness");

    assert_eq!(row["classification"].as_str(), Some("not-warm"));
    assert!(
        row["reasons"]
            .as_array()
            .expect("reasons")
            .contains(&json!("no-warm-worker"))
    );
    assert_eq!(
        row["recommended_workers"][0]["worker_id"].as_str(),
        Some("vmi-cold")
    );
}

#[test]
fn missing_telemetry_is_no_data() {
    let receipt = planner_json(&input_with(json!([]), "", json!([base_lane()])));
    let row = lane(&receipt, "module-microharness");

    assert_eq!(receipt["telemetry"]["state"].as_str(), Some("no-data"));
    assert_eq!(row["classification"].as_str(), Some("no-data"));
    assert!(
        row["reasons"]
            .as_array()
            .expect("reasons")
            .contains(&json!("no-worker-telemetry"))
    );
}

#[test]
fn stale_telemetry_degrades_instead_of_recommending_workers() {
    let receipt = planner_json(&input_with(
        json!([
            {
                "worker_id": "vmi-stale-warm",
                "available_slots": 1,
                "queue_depth": 0,
                "capabilities": ["linux", "rust"],
                "target_dir_families": ["rch_target_module_microharness_contract"]
            }
        ]),
        "2026-05-29T00:00:00Z",
        json!([base_lane()]),
    ));
    let row = lane(&receipt, "module-microharness");

    assert_eq!(receipt["telemetry"]["state"].as_str(), Some("stale"));
    assert_eq!(row["classification"].as_str(), Some("degraded"));
    assert_eq!(
        row["recommended_workers"]
            .as_array()
            .expect("workers")
            .len(),
        0
    );
    assert!(
        row["reasons"]
            .as_array()
            .expect("reasons")
            .contains(&json!("stale-worker-telemetry"))
    );
}

#[test]
fn saturated_workers_degrade_even_when_cache_is_warm() {
    let lane_input = base_lane();
    let cache_key = cache_key_for_lane(&lane_input);
    let receipt = planner_json(&input_with(
        json!([
            {
                "worker_id": "vmi-saturated",
                "available_slots": 0,
                "queue_depth": 6,
                "capabilities": ["linux", "rust"],
                "cache_keys": [cache_key]
            }
        ]),
        "2026-05-29T01:44:50Z",
        json!([lane_input]),
    ));
    let row = lane(&receipt, "module-microharness");

    assert_eq!(row["classification"].as_str(), Some("degraded"));
    assert!(
        row["reasons"]
            .as_array()
            .expect("reasons")
            .contains(&json!("warm-workers-saturated"))
    );
    assert_eq!(
        row["recommended_workers"]
            .as_array()
            .expect("workers")
            .len(),
        0
    );
}

#[test]
fn unsupported_lane_does_not_emit_worker_recommendations() {
    let mut unsupported = base_lane();
    unsupported["lane_id"] = json!("unsupported-wasm-lane");
    unsupported["unsupported"] = json!(true);

    let receipt = planner_json(&input_with(
        json!([
            {
                "worker_id": "vmi-any",
                "available_slots": 1,
                "queue_depth": 0,
                "capabilities": ["linux", "rust"]
            }
        ]),
        "2026-05-29T01:44:55Z",
        json!([unsupported]),
    ));
    let row = lane(&receipt, "unsupported-wasm-lane");

    assert_eq!(row["classification"].as_str(), Some("unsupported"));
    assert!(
        row["reasons"]
            .as_array()
            .expect("reasons")
            .contains(&json!("unsupported-lane"))
    );
    assert_eq!(
        row["recommended_workers"]
            .as_array()
            .expect("workers")
            .len(),
        0
    );
}

#[test]
fn output_is_dry_run_and_non_mutating() {
    let receipt = planner_json(&input_with(json!([]), "", json!([base_lane()])));

    assert_eq!(receipt["dry_run_only"].as_bool(), Some(true));
    assert_eq!(receipt["non_mutating"].as_bool(), Some(true));
    assert_eq!(
        receipt["forbidden_actions"]["runs_rch"].as_bool(),
        Some(false)
    );
    assert_eq!(
        receipt["forbidden_actions"]["runs_cargo"].as_bool(),
        Some(false)
    );
    assert_eq!(
        receipt["forbidden_actions"]["writes_remote_cache"].as_bool(),
        Some(false)
    );
    assert_eq!(
        receipt["contract"]["warmed_caches_are_advisory_only"].as_bool(),
        Some(true)
    );
    assert_eq!(
        receipt["contract"]["proof_must_still_execute"].as_bool(),
        Some(true)
    );
}
