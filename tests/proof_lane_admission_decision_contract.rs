#![allow(missing_docs)]

use serde_json::Value as JsonValue;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const SCRIPT_PATH: &str = "scripts/proof_lane_admission_decision.py";
const FIXTURE_DIR: &str = "tests/fixtures/proof_lane_admission_decision";
const GENERATED_AT: &str = "2026-05-29T02:20:00Z";

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).to_path_buf()
}

fn fixture_path(name: &str) -> PathBuf {
    repo_root().join(FIXTURE_DIR).join(name)
}

fn run_fixture(name: &str) -> JsonValue {
    let output = Command::new("python3")
        .current_dir(repo_root())
        .arg(SCRIPT_PATH)
        .arg("--input")
        .arg(fixture_path(name))
        .arg("--generated-at")
        .arg(GENERATED_AT)
        .arg("--output")
        .arg("json")
        .output()
        .unwrap_or_else(|error| panic!("run planner for {name}: {error}"));
    assert_success(name, &output);
    serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
        panic!(
            "parse planner JSON for {name}: {error}\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
    })
}

fn assert_success(name: &str, output: &Output) {
    assert!(
        output.status.success(),
        "planner failed for {name}\nstatus: {}\nstdout:\n{}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn decision(receipt: &JsonValue) -> &serde_json::Map<String, JsonValue> {
    receipt["decision"]
        .as_object()
        .expect("decision must be an object")
}

fn decision_name(receipt: &JsonValue) -> &str {
    decision(receipt)["admission_decision"]
        .as_str()
        .expect("admission decision")
}

fn reason_codes(receipt: &JsonValue) -> Vec<&str> {
    decision(receipt)["reason_codes"]
        .as_array()
        .expect("reason codes")
        .iter()
        .map(|value| value.as_str().expect("reason code string"))
        .collect()
}

fn assert_has_reason(receipt: &JsonValue, expected: &str) {
    let reasons = reason_codes(receipt);
    assert!(
        reasons.contains(&expected),
        "missing reason {expected}; got {reasons:?}"
    );
}

fn suggested_command(receipt: &JsonValue) -> &str {
    decision(receipt)["suggested_next_command"]
        .as_str()
        .expect("suggested command")
}

fn integrated(receipt: &JsonValue) -> &serde_json::Map<String, JsonValue> {
    receipt["integrated_operator_receipt"]
        .as_object()
        .expect("integrated operator receipt")
}

#[test]
fn receipts_are_dry_run_non_mutating_and_name_non_coverage() {
    let receipt = run_fixture("high_core_admit.json");
    assert_eq!(
        receipt["schema_version"].as_str(),
        Some("proof-lane-admission-decision-receipt-v1")
    );
    assert_eq!(
        receipt["input_schema_version"].as_str(),
        Some("proof-lane-admission-input-v1")
    );
    assert_eq!(receipt["generated_at"].as_str(), Some(GENERATED_AT));
    assert_eq!(receipt["dry_run_only"].as_bool(), Some(true));
    assert_eq!(receipt["non_mutating"].as_bool(), Some(true));

    let forbidden = receipt["forbidden_actions"]
        .as_object()
        .expect("forbidden actions");
    for key in [
        "runs_cargo",
        "runs_rch",
        "runs_git_mutation",
        "runs_beads_mutation",
        "sends_agent_mail",
        "writes_cache",
        "deletes_files",
    ] {
        assert_eq!(
            forbidden.get(key).and_then(JsonValue::as_bool),
            Some(false),
            "{key} must remain false"
        );
    }

    let non_coverage = receipt["non_coverage"]
        .as_array()
        .expect("non coverage")
        .iter()
        .map(|value| value.as_str().expect("non coverage string"))
        .collect::<Vec<_>>();
    assert!(non_coverage.contains(&"does not start proof lanes"));
    assert!(non_coverage.contains(&"does not prove Cargo/test success"));
    assert!(non_coverage.contains(&"does not make cache warmth correctness evidence"));

    let integrated = integrated(&receipt);
    assert_eq!(
        integrated["schema_version"].as_str(),
        Some("proof-lane-integrated-operator-receipt-v1")
    );
    assert_eq!(integrated["dry_run_only"].as_bool(), Some(true));
    assert_eq!(integrated["non_mutating"].as_bool(), Some(true));
    assert_eq!(
        integrated["planner_output_is_proof_evidence"].as_bool(),
        Some(false)
    );
    assert_eq!(
        integrated["cache_warmth_is_authoritative"].as_bool(),
        Some(false)
    );
    assert_eq!(
        integrated["actual_proof_commands_still_required"].as_bool(),
        Some(true)
    );
}

#[test]
fn high_core_high_ram_profile_admits_clean_cold_worker() {
    let receipt = run_fixture("high_core_admit.json");
    assert_eq!(decision_name(&receipt), "admit_now");
    assert_eq!(
        decision(&receipt)["proof_may_run_now"].as_bool(),
        Some(true)
    );
    assert_eq!(
        decision(&receipt)["recommended_worker_id"].as_str(),
        Some("rchw-cold-a")
    );
    assert_has_reason(&receipt, "host-large-core");
    assert_has_reason(&receipt, "worker-admissible");
    assert_has_reason(&receipt, "target-dir-isolated");
    assert!(suggested_command(&receipt).contains("RCH_PREFERRED_WORKER=rchw-cold-a"));
    assert!(suggested_command(&receipt).contains("RCH_REQUIRE_REMOTE=1"));
    assert!(suggested_command(&receipt).contains("CARGO_TARGET_DIR="));

    let integrated = integrated(&receipt);
    assert_eq!(integrated["admission_decision"].as_str(), Some("admit_now"));
    assert_eq!(
        integrated["operator_action"].as_str(),
        Some("run_suggested_command")
    );
    assert_eq!(
        integrated["dirty_tree_gate"]["admission_precondition"].as_str(),
        Some("clear")
    );
    assert_eq!(
        integrated["dirty_tree_gate"]["blocks_admission"].as_bool(),
        Some(false)
    );
    assert_eq!(
        integrated["proof_cache_warmth"]["classification"].as_str(),
        Some("not-warm")
    );
    assert_eq!(
        integrated["proof_cache_warmth"]["recommended_worker_id"].as_str(),
        Some("rchw-cold-a")
    );
    assert_eq!(
        integrated["proof_cache_warmth"]["preserves_agent_isolation"].as_bool(),
        Some(true)
    );
    assert_eq!(
        integrated["resource_pressure_summary"]["class"].as_str(),
        Some("healthy")
    );
    assert!(
        integrated["suggested_next_command"]
            .as_str()
            .expect("integrated command")
            .contains("CARGO_TARGET_DIR=")
    );
}

#[test]
fn low_memory_profile_queues_before_admission() {
    let receipt = run_fixture("low_memory_queue.json");
    assert_eq!(decision_name(&receipt), "queue");
    assert_eq!(
        decision(&receipt)["admission_precondition"].as_str(),
        Some("queue-for-memory")
    );
    assert_eq!(
        decision(&receipt)["proof_may_run_now"].as_bool(),
        Some(false)
    );
    assert_has_reason(&receipt, "low-memory-headroom");
}

#[test]
fn disk_pressure_profile_rejects_until_target_dir_headroom_recovers() {
    let receipt = run_fixture("disk_pressure_reject.json");
    assert_eq!(decision_name(&receipt), "reject");
    assert_eq!(
        decision(&receipt)["admission_precondition"].as_str(),
        Some("wait-for-disk-headroom")
    );
    assert_has_reason(&receipt, "low-target-dir-disk-headroom");
    assert_eq!(
        receipt["disk_summary"]["sufficient_for_lane"].as_bool(),
        Some(false)
    );
}

#[test]
fn peer_owned_dirty_paths_force_dirty_tree_handoff() {
    let receipt = run_fixture("dirty_tree_peer_owned.json");
    assert_eq!(decision_name(&receipt), "wait_for_dirty_tree_handoff");
    assert_has_reason(&receipt, "peer-owned-dirty-path");
    assert_has_reason(&receipt, "reservation-handoff-required");
    assert_eq!(
        receipt["dirty_tree"]["classification"].as_str(),
        Some("peer-owned-source")
    );
    assert_eq!(
        receipt["dirty_tree"]["peer_owned_paths"][0].as_str(),
        Some("src/net/tcp/stream.rs")
    );
    let gate = &integrated(&receipt)["dirty_tree_gate"];
    assert_eq!(gate["blocks_admission"].as_bool(), Some(true));
    assert_eq!(
        gate["blockers"][0]["kind"].as_str(),
        Some("peer_owned_dirty_path")
    );
    assert_eq!(
        gate["blockers"][0]["path"].as_str(),
        Some("src/net/tcp/stream.rs")
    );
    assert_eq!(
        integrated(&receipt)["operator_action"].as_str(),
        Some("wait_for_dirty_tree_handoff")
    );
}

#[test]
fn active_peer_reservation_without_dirty_path_forces_reservation_handoff() {
    let receipt = run_fixture("peer_reservation_handoff.json");
    assert_eq!(decision_name(&receipt), "wait_for_reservation_handoff");
    assert_has_reason(&receipt, "active-peer-reservation");
    assert_has_reason(&receipt, "reservation-handoff-required");
    let holders = receipt["reservation_holders"].as_array().expect("holders");
    assert_eq!(holders.len(), 1);
    assert_eq!(holders[0]["agent"].as_str(), Some("ProudSwan"));
    assert_eq!(
        holders[0]["path_pattern"].as_str(),
        Some("tests/tokio_process_lifecycle_parity.rs")
    );
    let gate = &integrated(&receipt)["dirty_tree_gate"];
    assert_eq!(gate["blocks_admission"].as_bool(), Some(true));
    assert_eq!(
        gate["blockers"][0]["kind"].as_str(),
        Some("active_peer_reservation")
    );
    assert_eq!(gate["blockers"][0]["agent"].as_str(), Some("ProudSwan"));
}

#[test]
fn saturated_workers_queue_without_local_fallback() {
    let receipt = run_fixture("worker_saturation_queue.json");
    assert_eq!(decision_name(&receipt), "queue");
    assert_eq!(
        decision(&receipt)["admission_precondition"].as_str(),
        Some("queue-for-worker")
    );
    assert_has_reason(&receipt, "remote-worker-saturated");
    assert_eq!(
        receipt["worker_summary"]["admissible_worker_count"].as_u64(),
        Some(0)
    );
}

#[test]
fn warm_worker_is_preferred_but_not_correctness_evidence() {
    let receipt = run_fixture("warm_worker_preference.json");
    assert_eq!(decision_name(&receipt), "use_warmed_worker");
    assert_eq!(
        decision(&receipt)["recommended_worker_id"].as_str(),
        Some("rchw-warm-a")
    );
    assert_has_reason(&receipt, "warm-worker-preferred");
    assert!(suggested_command(&receipt).contains("RCH_PREFERRED_WORKER=rchw-warm-a"));
    let has_cache_warmth_non_coverage = receipt["non_coverage"]
        .as_array()
        .expect("non coverage")
        .iter()
        .map(|value| value.as_str().expect("non coverage string"))
        .any(|entry| entry == "does not make cache warmth correctness evidence");
    assert!(has_cache_warmth_non_coverage);
}

#[test]
fn stale_cache_warmth_never_overrides_dirty_tree_blockers() {
    let receipt = run_fixture("dirty_tree_peer_owned.json");
    assert_eq!(decision_name(&receipt), "wait_for_dirty_tree_handoff");

    let integrated = integrated(&receipt);
    assert_eq!(
        integrated["proof_cache_warmth"]["classification"].as_str(),
        Some("warm")
    );
    assert_eq!(
        integrated["proof_cache_warmth"]["telemetry_state"].as_str(),
        Some("stale")
    );
    assert_eq!(
        integrated["proof_cache_warmth"]["overridden_by_admission_blockers"].as_bool(),
        Some(true)
    );
    assert_eq!(
        integrated["proof_cache_warmth"]["cache_warmth_is_correctness_evidence"].as_bool(),
        Some(false)
    );
    assert_eq!(
        integrated["dirty_tree_gate"]["blocks_admission"].as_bool(),
        Some(true)
    );
    assert_eq!(
        integrated["admission_decision"].as_str(),
        Some("wait_for_dirty_tree_handoff")
    );
    assert_eq!(integrated["proof_may_run_now"].as_bool(), Some(false));
}

#[test]
fn oversized_proof_pack_returns_split_lane_receipt() {
    let receipt = run_fixture("oversized_split_lane.json");
    assert_eq!(decision_name(&receipt), "split_lane");
    assert_has_reason(&receipt, "oversized-proof-pack");
    assert_has_reason(&receipt, "split-lane-recommended");
    let split = decision(&receipt)["split_plan"]
        .as_object()
        .expect("split plan");
    assert!(
        split["recommended_shards"].as_u64().expect("shards") >= 2,
        "oversized lane must recommend at least two shards"
    );
    assert_eq!(split["split_reason"].as_str(), Some("oversized-proof-pack"));
}
