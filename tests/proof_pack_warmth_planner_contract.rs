//! Contract tests for the dry-run proof-pack warmth planner.

#![allow(missing_docs)]

use serde_json::{Value, json};
use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Output};

const SCRIPT_PATH: &str = "scripts/proof_pack_warmth_planner.py";
const CONTRACT_PATH: &str = "artifacts/proof_pack_cache_key_contract_v1.json";
const EXPECTED_SAVINGS_PATH: &str = "artifacts/proof_pack_warmth_expected_savings_v1.json";
const FIXTURE_DIR: &str = "tests/fixtures/proof_pack_warmth_planner";
const GENERATED_AT: &str = "2026-05-29T01:45:00Z";

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn fixture_json(name: &str) -> Value {
    let path = repo_root().join(FIXTURE_DIR).join(name);
    let raw = fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("read fixture {}: {error}", path.display()));
    serde_json::from_str(&raw)
        .unwrap_or_else(|error| panic!("parse fixture {}: {error}", path.display()))
}

fn artifact_json(path: &str) -> Value {
    let path = repo_root().join(path);
    let raw = fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("read artifact {}: {error}", path.display()));
    serde_json::from_str(&raw)
        .unwrap_or_else(|error| panic!("parse artifact {}: {error}", path.display()))
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
    assert_eq!(
        row["worker_warmth_evidence"]["cache_warmth_is_correctness_evidence"].as_bool(),
        Some(false)
    );
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
    assert_eq!(
        receipt["operator_receipt"]["dry_run_only"].as_bool(),
        Some(true)
    );
    assert_eq!(
        receipt["operator_receipt"]["planner_output_is_proof_evidence"].as_bool(),
        Some(false)
    );
    assert_eq!(
        receipt["operator_receipt"]["actual_proof_commands_still_required"].as_bool(),
        Some(true)
    );
}

#[test]
fn fixture_receipts_explain_two_current_proof_families() {
    let receipt = planner_json(&fixture_json("two_family_fresh.json"));

    assert_eq!(receipt["summary"]["lane_count"].as_u64(), Some(2));
    let module = lane(&receipt, "module-microharness");
    let module_evidence = &module["worker_warmth_evidence"];
    assert_eq!(module["classification"].as_str(), Some("warm"));
    assert_eq!(
        module_evidence["schema_version"].as_str(),
        Some("proof-pack-worker-warmth-evidence-v1")
    );
    assert_eq!(
        module_evidence["observed_rch_worker_id"].as_str(),
        Some("vmi-module-warm")
    );
    assert_eq!(
        module_evidence["sampled_at"].as_str(),
        Some("2026-05-29T01:44:30Z")
    );
    assert_eq!(
        module_evidence["proof_lane_family"].as_str(),
        Some("module-microharness")
    );
    assert_eq!(
        module_evidence["cache_key_fingerprint"].as_str(),
        module["cache_key_fingerprint"].as_str()
    );
    assert_eq!(
        module_evidence["matching_target_dir_family"].as_str(),
        Some("rch_target_module_microharness_contract")
    );
    assert!(
        module_evidence["warmth_basis"]
            .as_array()
            .expect("warmth basis")
            .contains(&json!("target-dir-family"))
    );
    assert_eq!(
        module_evidence["queue_pressure"]["class"].as_str(),
        Some("low")
    );
    assert_eq!(
        module_evidence["estimated_compile_savings_seconds"].as_u64(),
        Some(780)
    );
    assert_eq!(
        module_evidence["estimated_savings_band"].as_str(),
        Some("high")
    );
    assert_eq!(module_evidence["confidence_class"].as_str(), Some("medium"));
    assert_eq!(
        module_evidence["fallback_recommendation"].as_str(),
        Some("run-proof-on-recommended-warm-worker")
    );
    assert_eq!(
        module_evidence["cache_warmth_is_correctness_evidence"].as_bool(),
        Some(false)
    );

    let selector = lane(&receipt, "touched-surface-selector");
    let selector_evidence = &selector["worker_warmth_evidence"];
    assert_eq!(selector["classification"].as_str(), Some("not-warm"));
    assert_eq!(
        selector_evidence["observed_rch_worker_id"].as_str(),
        Some("vmi-selector-cold")
    );
    assert_eq!(
        selector_evidence["proof_lane_family"].as_str(),
        Some("touched-surface-selector")
    );
    assert_eq!(
        selector_evidence["matching_target_dir_family"].as_str(),
        Some("")
    );
    assert!(
        selector_evidence["warmth_basis"]
            .as_array()
            .expect("selector warmth basis")
            .contains(&json!("compatible-cold-worker"))
    );
    assert_eq!(
        selector_evidence["queue_pressure"]["class"].as_str(),
        Some("low")
    );
    assert_eq!(
        selector_evidence["estimated_compile_savings_seconds"].as_u64(),
        Some(60)
    );
    assert_eq!(
        selector_evidence["estimated_savings_band"].as_str(),
        Some("none")
    );
    assert_eq!(
        selector_evidence["confidence_class"].as_str(),
        Some("medium")
    );
    assert_eq!(
        selector_evidence["fallback_recommendation"].as_str(),
        Some("run-proof-on-compatible-cold-worker")
    );
}

#[test]
fn fixture_missing_telemetry_receipt_fails_closed_without_worker_claims() {
    let receipt = planner_json(&fixture_json("missing_telemetry.json"));
    let row = lane(&receipt, "module-microharness");
    let evidence = &row["worker_warmth_evidence"];

    assert_eq!(receipt["telemetry"]["state"].as_str(), Some("no-data"));
    assert_eq!(row["classification"].as_str(), Some("no-data"));
    assert_eq!(evidence["observed_rch_worker_id"].as_str(), Some(""));
    assert_eq!(evidence["sampled_at"].as_str(), Some(""));
    assert_eq!(
        evidence["telemetry_freshness"]["state"].as_str(),
        Some("no-data")
    );
    assert_eq!(
        evidence["queue_pressure"]["class"].as_str(),
        Some("unknown")
    );
    assert_eq!(evidence["estimated_savings_band"].as_str(), Some("unknown"));
    assert_eq!(evidence["confidence_class"].as_str(), Some("low"));
    assert_eq!(
        evidence["fallback_recommendation"].as_str(),
        Some("collect-rch-worker-telemetry-before-selecting-worker")
    );
    assert_eq!(
        evidence["cache_warmth_is_correctness_evidence"].as_bool(),
        Some(false)
    );
}

#[test]
fn fixture_stale_telemetry_receipt_names_stale_worker_but_requires_replan() {
    let receipt = planner_json(&fixture_json("stale_telemetry.json"));
    let row = lane(&receipt, "module-microharness");
    let evidence = &row["worker_warmth_evidence"];

    assert_eq!(receipt["telemetry"]["state"].as_str(), Some("stale"));
    assert_eq!(row["classification"].as_str(), Some("degraded"));
    assert_eq!(
        evidence["observed_rch_worker_id"].as_str(),
        Some("vmi-stale-module-warm")
    );
    assert_eq!(
        evidence["telemetry_freshness"]["state"].as_str(),
        Some("stale")
    );
    assert_eq!(
        evidence["telemetry_freshness"]["age_seconds"].as_u64(),
        Some(6300)
    );
    assert_eq!(
        evidence["matching_target_dir_family"].as_str(),
        Some("rch_target_module_microharness_contract")
    );
    assert_eq!(evidence["estimated_savings_band"].as_str(), Some("unknown"));
    assert_eq!(evidence["confidence_class"].as_str(), Some("low"));
    assert_eq!(
        evidence["fallback_recommendation"].as_str(),
        Some("refresh-rch-telemetry-and-replan")
    );
    assert_eq!(
        evidence["cache_warmth_is_correctness_evidence"].as_bool(),
        Some(false)
    );
}

#[test]
fn mismatched_cache_key_fails_closed_to_cold_worker() {
    let receipt = planner_json(&fixture_json("mismatched_cache_key.json"));
    let row = lane(&receipt, "module-microharness");
    let evidence = &row["worker_warmth_evidence"];

    assert_eq!(receipt["telemetry"]["state"].as_str(), Some("fresh"));
    assert_eq!(row["classification"].as_str(), Some("not-warm"));
    assert!(
        row["reasons"]
            .as_array()
            .expect("reasons")
            .contains(&json!("no-warm-worker"))
    );
    assert_eq!(
        row["recommended_workers"][0]["worker_id"].as_str(),
        Some("vmi-mismatched-cache")
    );
    assert_eq!(
        row["recommended_workers"][0]["matches_cache_key"].as_bool(),
        Some(false)
    );
    assert_eq!(
        row["recommended_workers"][0]["matches_target_dir_family"].as_bool(),
        Some(false)
    );
    assert_eq!(
        evidence["observed_rch_worker_id"].as_str(),
        Some("vmi-mismatched-cache")
    );
    assert_eq!(evidence["matching_target_dir_family"].as_str(), Some(""));
    assert!(
        evidence["warmth_basis"]
            .as_array()
            .expect("warmth basis")
            .contains(&json!("compatible-cold-worker"))
    );
    assert_eq!(evidence["estimated_savings_band"].as_str(), Some("none"));
    assert_eq!(evidence["confidence_class"].as_str(), Some("medium"));
    assert_eq!(
        evidence["cache_warmth_is_correctness_evidence"].as_bool(),
        Some(false)
    );
}

#[test]
fn operator_receipt_names_required_real_proof_lanes_and_isolated_commands() {
    let receipt = planner_json(&fixture_json("mismatched_cache_key.json"));
    let operator = &receipt["operator_receipt"];

    assert_eq!(
        operator["schema_version"].as_str(),
        Some("proof-pack-warmth-operator-receipt-v1")
    );
    assert_eq!(operator["dry_run_only"].as_bool(), Some(true));
    assert_eq!(
        operator["cache_warmth_is_authoritative"].as_bool(),
        Some(false)
    );
    assert_eq!(
        operator["planner_output_is_proof_evidence"].as_bool(),
        Some(false)
    );
    assert_eq!(
        operator["actual_proof_commands_still_required"].as_bool(),
        Some(true)
    );
    assert_eq!(
        operator["all_command_templates_preserve_agent_isolation"].as_bool(),
        Some(true)
    );

    let lane_command = operator["lane_command_templates"][0]["actual_proof_command"]
        .as_str()
        .expect("lane command");
    assert!(
        lane_command
            .starts_with("rch exec -- env CARGO_TARGET_DIR=\"${TMPDIR:-/tmp}/rch_target_MistyCat_")
    );
    assert_eq!(
        operator["lane_command_templates"][0]["runs_now"].as_bool(),
        Some(false)
    );

    let required = operator["broader_proof_lanes_still_required"]
        .as_array()
        .expect("required proof lanes");
    assert_eq!(required.len(), 2);
    assert_eq!(
        required[0]["lane_id"].as_str(),
        Some("proof-pack-warmth-planner-contract")
    );
    assert_eq!(
        required[0]["command"].as_str(),
        Some("cargo test --test proof_pack_warmth_planner_contract")
    );
    assert_eq!(required[1]["lane_id"].as_str(), Some("release-gate-clippy"));
    assert_eq!(
        required[1]["command"].as_str(),
        Some("cargo clippy --all-targets -- -D warnings")
    );
}

#[test]
fn expected_savings_artifact_matches_two_family_planner_receipt() {
    let artifact = artifact_json(EXPECTED_SAVINGS_PATH);
    let receipt = planner_json(&fixture_json("two_family_fresh.json"));

    assert_eq!(
        artifact["schema_version"].as_str(),
        Some("proof-pack-warmth-expected-savings-v1")
    );
    assert_eq!(
        artifact["source_fixture"].as_str(),
        Some("tests/fixtures/proof_pack_warmth_planner/two_family_fresh.json")
    );
    assert_eq!(
        artifact["safety_contract"]["dry_run_only"].as_bool(),
        Some(true)
    );
    assert_eq!(
        artifact["safety_contract"]["cache_warmth_is_correctness_evidence"].as_bool(),
        Some(false)
    );
    assert_eq!(
        artifact["safety_contract"]["proof_must_still_execute"].as_bool(),
        Some(true)
    );
    assert_eq!(artifact["summary"]["proof_family_count"].as_u64(), Some(2));

    for family in artifact["proof_families"]
        .as_array()
        .expect("proof families")
    {
        let lane_id = family["lane_id"].as_str().expect("lane id");
        let row = lane(&receipt, lane_id);
        let evidence = &row["worker_warmth_evidence"];

        assert_eq!(
            family["proof_lane_family"].as_str(),
            evidence["proof_lane_family"].as_str()
        );
        assert_eq!(
            family["classification"].as_str(),
            row["classification"].as_str()
        );
        assert_eq!(
            family["cache_key_fingerprint"].as_str(),
            row["cache_key_fingerprint"].as_str()
        );
        assert_eq!(
            family["observed_rch_worker_id"].as_str(),
            evidence["observed_rch_worker_id"].as_str()
        );
        assert_eq!(
            family["matching_target_dir_family"].as_str(),
            evidence["matching_target_dir_family"].as_str()
        );
        assert_eq!(
            family["queue_pressure"]["class"].as_str(),
            evidence["queue_pressure"]["class"].as_str()
        );
        assert_eq!(
            family["queue_pressure"]["queue_depth"].as_u64(),
            evidence["queue_pressure"]["queue_depth"].as_u64()
        );
        assert_eq!(
            family["queue_pressure"]["available_slots"].as_u64(),
            evidence["queue_pressure"]["available_slots"].as_u64()
        );
        assert_eq!(
            family["expected_compile_savings_seconds"].as_u64(),
            evidence["estimated_compile_savings_seconds"].as_u64()
        );
        assert_eq!(
            family["expected_compile_savings_band"].as_str(),
            evidence["estimated_savings_band"].as_str()
        );
        assert_eq!(
            family["fallback_recommendation"].as_str(),
            evidence["fallback_recommendation"].as_str()
        );
    }

    let required = artifact["required_real_proof_lanes"]
        .as_array()
        .expect("required proof lanes");
    assert_eq!(required.len(), 1);
    assert_eq!(
        required[0]["command"].as_str(),
        Some("cargo test --test proof_pack_warmth_planner_contract")
    );
}
