//! Contract tests for the memory-residency replay E2E lane.

#![allow(missing_docs)]

use asupersync::runtime::config::{
    ArenaLocalityAccessModel, ArenaLocalityPolicy, ArenaTemperaturePolicy, RuntimeCapacityHints,
    RuntimeConfig, TraceStorageProfile, WorkerCohortMapping,
};
use asupersync::runtime::resource_monitor::{
    MonitorConfig, ResourceMeasurement, ResourceMonitor, ResourceType, RuntimePressureSnapshot,
    RuntimePressureVerdict,
};
use asupersync::runtime::{
    ArtifactMemoryPressureSnapshot, MemoryResidencyAccountingSnapshot, MemoryResidencyDecision,
    MemoryResidencyPolicy, MemoryResidencyPolicyInput, MemoryResidencyRecordPoolCounters,
    ProofPackWarmthTelemetry,
};
use serde_json::Value;
use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;
use std::process::Command;

const CONTRACT_PATH: &str = "artifacts/memory_residency_replay_e2e_contract_v1.json";
const DOCS_PATH: &str = "docs/proof/memory_residency_replay_e2e.md";
const RUNNER_PATH: &str = "scripts/run_memory_residency_replay_e2e.sh";
const HELPER_PATH: &str = "scripts/memory_residency_replay_e2e.py";
const ORCHESTRATOR_PATH: &str = "scripts/run_all_e2e.sh";
const MANIFEST_PATH: &str = "artifacts/proof_lane_manifest_v1.json";
const STATUS_PATH: &str = "artifacts/proof_status_snapshot_v1.json";
const POLICY_CONTRACT_PATH: &str = "artifacts/memory_residency_policy_contract_v1.json";
const ACCOUNTING_CONTRACT_PATH: &str = "artifacts/memory_residency_accounting_snapshot_v1.json";

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn repo_path(relative: &str) -> PathBuf {
    repo_root().join(relative)
}

fn read_repo_file(relative: &str) -> String {
    fs::read_to_string(repo_path(relative))
        .unwrap_or_else(|error| panic!("read {relative}: {error}"))
}

fn json(relative: &str) -> Value {
    serde_json::from_str(&read_repo_file(relative))
        .unwrap_or_else(|error| panic!("parse {relative}: {error}"))
}

fn array<'a>(value: &'a Value, key: &str) -> &'a [Value] {
    value[key]
        .as_array()
        .unwrap_or_else(|| panic!("{key} array"))
        .as_slice()
}

fn string_field<'a>(value: &'a Value, key: &str) -> &'a str {
    value[key]
        .as_str()
        .unwrap_or_else(|| panic!("{key} string"))
}

fn string_set(value: &Value, key: &str) -> BTreeSet<String> {
    array(value, key)
        .iter()
        .map(|entry| entry.as_str().expect("string entry").to_string())
        .collect()
}

fn find_by_id<'a>(rows: &'a [Value], key: &str, expected: &str) -> &'a Value {
    rows.iter()
        .find(|row| row.get(key).and_then(Value::as_str) == Some(expected))
        .unwrap_or_else(|| panic!("missing {key}={expected}"))
}

fn assert_contains_all(haystack: &str, needles: &[&str]) {
    for needle in needles {
        assert!(haystack.contains(needle), "missing {needle}");
    }
}

fn large_host_worker_cohort_map() -> WorkerCohortMapping {
    WorkerCohortMapping::new(vec![
        0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 2, 2, 2, 2, 2, 2, 2, 2, 3, 3, 3, 3, 3, 3,
        3, 3, 4, 4, 4, 4, 4, 4, 4, 4, 5, 5, 5, 5, 5, 5, 5, 5, 6, 6, 6, 6, 6, 6, 6, 6, 7, 7, 7, 7,
        7, 7, 7, 7,
    ])
}

fn skewed_access_model() -> ArenaLocalityAccessModel {
    ArenaLocalityAccessModel {
        task_arena_touches_by_cohort: vec![3200, 640, 640, 640, 640, 640, 640, 640],
        region_arena_touches_by_cohort: vec![1024, 128, 128, 128, 128, 128, 128, 128],
        obligation_arena_touches_by_cohort: vec![768, 768, 128, 128, 128, 128, 128, 128],
        task_record_pool_touches_by_cohort: vec![3200, 640, 640, 640, 640, 640, 640, 640],
    }
}

fn balanced_access_model() -> ArenaLocalityAccessModel {
    ArenaLocalityAccessModel {
        task_arena_touches_by_cohort: vec![1024; 8],
        region_arena_touches_by_cohort: vec![256; 8],
        obligation_arena_touches_by_cohort: vec![512; 8],
        task_record_pool_touches_by_cohort: vec![1024; 8],
    }
}

fn locality_report(
    access_model: &ArenaLocalityAccessModel,
    budget_bps: u16,
) -> asupersync::runtime::config::ArenaLocalityReport {
    RuntimeConfig {
        worker_threads: 64,
        worker_cohort_map: Some(large_host_worker_cohort_map()),
        capacity_hints: Some(RuntimeCapacityHints::from_expected_concurrent_tasks(4096)),
        ..RuntimeConfig::default()
    }
    .arena_locality_report(
        ArenaLocalityPolicy::CohortPinned {
            min_topology_confidence_percent: 80,
            remote_touch_budget_bps: budget_bps,
            accounting_epoch: 23,
        },
        Some(95),
        access_model,
    )
}

fn roomy_cache_snapshot() -> ArtifactMemoryPressureSnapshot {
    ArtifactMemoryPressureSnapshot {
        resident_bytes: 128 * 1024 * 1024,
        max_resident_bytes: 8 * 1024 * 1024 * 1024,
        hot_resident_bytes: 96 * 1024 * 1024,
        cold_resident_bytes: 32 * 1024 * 1024,
        spill_eligible_bytes: 2 * 1024 * 1024 * 1024,
        remote_numa_bytes: 0,
        pressure_bps: 1_500,
        high_pressure: false,
        duplicate_bytes_avoided: 0,
        artifact_count: 12,
    }
}

fn exhausted_cache_snapshot() -> ArtifactMemoryPressureSnapshot {
    ArtifactMemoryPressureSnapshot {
        resident_bytes: 490 * 1024 * 1024,
        max_resident_bytes: 512 * 1024 * 1024,
        hot_resident_bytes: 420 * 1024 * 1024,
        cold_resident_bytes: 70 * 1024 * 1024,
        spill_eligible_bytes: 32 * 1024 * 1024,
        remote_numa_bytes: 0,
        pressure_bps: 9_100,
        high_pressure: true,
        duplicate_bytes_avoided: 0,
        artifact_count: 48,
    }
}

fn critical_pressure_snapshot() -> RuntimePressureSnapshot {
    let monitor = ResourceMonitor::new(MonitorConfig::default());
    monitor.pressure().update_measurement(
        ResourceType::Memory,
        ResourceMeasurement::new(98, 80, 95, 100),
    );
    monitor.runtime_pressure_snapshot(None, None)
}

fn counters() -> MemoryResidencyRecordPoolCounters {
    MemoryResidencyRecordPoolCounters {
        task_hits: 11,
        task_misses: 2,
        task_recycles: 3,
        region_hits: 5,
        region_misses: 1,
        region_recycles: 2,
        obligation_hits: 7,
        obligation_misses: 4,
        obligation_recycles: 6,
    }
}

fn base_input<'a>(
    locality: &'a asupersync::runtime::config::ArenaLocalityReport,
    cache: &'a ArtifactMemoryPressureSnapshot,
) -> MemoryResidencyPolicyInput<'a> {
    MemoryResidencyPolicyInput::new(
        RuntimeCapacityHints::from_expected_concurrent_tasks(4096),
        TraceStorageProfile::LargeMemory256G,
        ArenaTemperaturePolicy::TieredColdEvidence,
    )
    .with_locality_report(locality, 30)
    .with_artifact_cache_pressure(cache)
    .with_proof_pack_warmth(ProofPackWarmthTelemetry::new(true, true, 30, 900))
}

fn snapshot_for(
    decision: &MemoryResidencyDecision,
    input: &MemoryResidencyPolicyInput<'_>,
) -> MemoryResidencyAccountingSnapshot {
    MemoryResidencyAccountingSnapshot::from_decision(decision, input, 123_456, Some(counters()))
}

fn run_policy_scenario(
    scenario_id: &str,
) -> (MemoryResidencyDecision, MemoryResidencyAccountingSnapshot) {
    let policy = MemoryResidencyPolicy::experimental_opt_in();
    match scenario_id {
        "fresh_topology_warm_evidence" => {
            let locality = locality_report(&skewed_access_model(), 6500);
            let cache = roomy_cache_snapshot();
            let input = base_input(&locality, &cache);
            let decision = policy.decide(&input);
            let snapshot = snapshot_for(&decision, &input);
            (decision, snapshot)
        }
        "stale_topology_fallback" => {
            let locality = locality_report(&skewed_access_model(), 6500);
            let cache = roomy_cache_snapshot();
            let input = base_input(&locality, &cache).with_locality_report(&locality, 901);
            let decision = policy.decide(&input);
            let snapshot = snapshot_for(&decision, &input);
            (decision, snapshot)
        }
        "no_win_locality" => {
            let locality = locality_report(&balanced_access_model(), 9000);
            let cache = roomy_cache_snapshot();
            let input = base_input(&locality, &cache);
            let decision = policy.decide(&input);
            let snapshot = snapshot_for(&decision, &input);
            (decision, snapshot)
        }
        "critical_memory_pressure" => {
            let locality = locality_report(&skewed_access_model(), 6500);
            let cache = roomy_cache_snapshot();
            let pressure = critical_pressure_snapshot();
            assert_eq!(pressure.overall_verdict, RuntimePressureVerdict::Critical);
            let input = base_input(&locality, &cache).with_runtime_pressure(&pressure);
            let decision = policy.decide(&input);
            let snapshot = snapshot_for(&decision, &input);
            (decision, snapshot)
        }
        "cold_evidence_budget_exhausted" => {
            let locality = locality_report(&skewed_access_model(), 6500);
            let cache = exhausted_cache_snapshot();
            let input = base_input(&locality, &cache);
            let decision = policy.decide(&input);
            let snapshot = snapshot_for(&decision, &input);
            (decision, snapshot)
        }
        "artifact_cache_pressure_spill_available" => {
            let locality = locality_report(&skewed_access_model(), 6500);
            let cache = ArtifactMemoryPressureSnapshot {
                pressure_bps: 8_700,
                high_pressure: true,
                spill_eligible_bytes: u64::MAX,
                ..roomy_cache_snapshot()
            };
            let input = base_input(&locality, &cache);
            let decision = policy.decide(&input);
            let snapshot = snapshot_for(&decision, &input);
            (decision, snapshot)
        }
        other => panic!("unknown replay scenario {other}"),
    }
}

#[test]
fn contract_artifact_pins_sources_scenarios_artifacts_and_no_claims() {
    let contract = json(CONTRACT_PATH);
    assert_eq!(
        string_field(&contract, "schema_version"),
        "memory-residency-replay-e2e-contract-v1"
    );
    assert_eq!(
        string_field(&contract, "bead_id"),
        "asupersync-memory-residency-control-ho2itz.4"
    );
    assert_eq!(
        string_field(&contract, "parent_bead_id"),
        "asupersync-memory-residency-control-ho2itz"
    );
    assert_eq!(string_field(&contract, "status"), "contract_guarded");

    for path in [
        string_field(&contract["source_of_truth"], "contract"),
        string_field(&contract["source_of_truth"], "runner"),
        string_field(&contract["source_of_truth"], "helper"),
        string_field(&contract["source_of_truth"], "contract_test"),
        string_field(&contract["source_of_truth"], "docs"),
        string_field(&contract["source_of_truth"], "orchestrator"),
        string_field(&contract["source_of_truth"], "proof_lane_manifest"),
        string_field(&contract["source_of_truth"], "proof_status_snapshot"),
        string_field(&contract["source_of_truth"], "upstream_policy_contract"),
        string_field(&contract["source_of_truth"], "upstream_accounting_contract"),
    ] {
        assert!(repo_path(path).exists(), "{path} must exist");
    }

    assert_eq!(
        string_field(&contract["suite"], "suite_id"),
        "memory_residency_replay_e2e"
    );
    assert_eq!(
        string_field(&contract["suite"], "scenario_id"),
        "E2E-SUITE-MEMORY-RESIDENCY-REPLAY"
    );
    assert_eq!(
        contract["large_host_fixture"]["cpu_cores"].as_u64(),
        Some(64)
    );
    assert_eq!(
        contract["large_host_fixture"]["memory_gib"].as_u64(),
        Some(256)
    );
    assert_eq!(
        contract["large_host_fixture"]["deterministic_replay_only"].as_bool(),
        Some(true)
    );
    assert_eq!(
        contract["large_host_fixture"]["live_host_probe"].as_bool(),
        Some(false)
    );

    let command = string_field(&contract["proof_lane"], "command");
    assert!(command.starts_with("RCH_REQUIRE_REMOTE=1 rch exec -- env "));
    assert!(command.contains("CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_"));
    assert!(
        command.contains("cargo test -p asupersync --test memory_residency_replay_e2e_contract")
    );

    let required = string_set(&contract, "required_scenario_ids");
    let actual = array(&contract, "replay_scenarios")
        .iter()
        .map(|row| string_field(row, "scenario_id").to_string())
        .collect::<BTreeSet<_>>();
    assert_eq!(required, actual);
    assert!(
        actual.len() >= 5,
        "M4 replay must keep at least five deterministic scenarios"
    );
    for scenario in [
        "fresh_topology_warm_evidence",
        "stale_topology_fallback",
        "no_win_locality",
        "critical_memory_pressure",
        "cold_evidence_budget_exhausted",
    ] {
        assert!(actual.contains(scenario), "missing {scenario}");
    }

    let stale = find_by_id(
        array(&contract, "replay_scenarios"),
        "scenario_id",
        "stale_topology_fallback",
    );
    assert_eq!(stale["expected"]["policy_tier"].as_str(), Some("fallback"));
    assert_eq!(stale["expected"]["snapshot_status"].as_str(), Some("stale"));
    assert_eq!(stale["expected"]["fail_closed"].as_bool(), Some(true));
    assert!(
        stale["input_fixture"]["topology_age_seconds"]
            .as_u64()
            .expect("stale topology age")
            > 900
    );

    assert_eq!(
        contract["benchmark_evidence"]["included"].as_bool(),
        Some(false)
    );
    let no_claims = string_set(&contract, "no_claim_boundaries");
    for boundary in [
        "No fresh benchmark evidence is included in this contract.",
        "The replay runner emits deterministic fixture evidence only and does not probe live host topology.",
    ] {
        assert!(no_claims.contains(boundary), "missing boundary {boundary}");
    }
}

#[test]
fn replay_scenarios_match_policy_and_accounting_outputs() {
    let contract = json(CONTRACT_PATH);
    for row in array(&contract, "replay_scenarios") {
        let scenario_id = string_field(row, "scenario_id");
        let expected = &row["expected"];
        let (decision, snapshot) = run_policy_scenario(scenario_id);

        assert_eq!(
            decision.selected_tier.as_str(),
            expected["policy_tier"].as_str(),
            "{scenario_id}: policy tier drift"
        );
        assert_eq!(
            snapshot.status.as_str(),
            expected["snapshot_status"].as_str(),
            "{scenario_id}: snapshot status drift"
        );
        assert_eq!(
            decision.live_task_action.as_str(),
            expected["live_task_action"].as_str(),
            "{scenario_id}: live-task action drift"
        );
        assert_eq!(snapshot.selected_tier, decision.selected_tier);
        assert_eq!(snapshot.policy_enabled, decision.policy_enabled);

        let expected_reasons = string_set(expected, "required_reason_codes");
        let actual_reasons = decision
            .reason_codes
            .iter()
            .map(|reason| reason.as_str().to_string())
            .collect::<BTreeSet<_>>();
        assert_eq!(
            actual_reasons, expected_reasons,
            "{scenario_id}: decision reason-code drift"
        );
        assert_eq!(
            snapshot
                .reason_codes
                .iter()
                .map(|reason| reason.as_str().to_string())
                .collect::<BTreeSet<_>>(),
            expected_reasons,
            "{scenario_id}: snapshot reason-code drift"
        );
    }
}

#[test]
fn runner_and_docs_capture_artifacts_failure_contract_and_no_deletion_policy() {
    let runner = read_repo_file(RUNNER_PATH);
    let helper = read_repo_file(HELPER_PATH);
    let docs = read_repo_file(DOCS_PATH);

    assert_contains_all(
        &runner,
        &[
            "memory_residency_replay_e2e",
            "memory_residency_replay_e2e_contract_v1.json",
            "memory_residency_replay_e2e.py",
            "Summary:",
            "Artifacts:",
            "copy-paste RCH command",
        ],
    );
    assert_contains_all(
        &helper,
        &[
            "memory-residency-replay-e2e-event-v1",
            "e2e-suite-summary-v3",
            "scenario_report.json",
            "operator_report.md",
            "missing input scenario_id=",
            "stale input scenario_id=stale_topology_fallback",
            "copy-paste RCH command",
        ],
    );
    assert_contains_all(
        &docs,
        &[
            CONTRACT_PATH,
            RUNNER_PATH,
            "summary.json",
            "events.ndjson",
            "scenario_report.json",
            "operator_report.md",
            "does not prove live host throughput",
        ],
    );

    for (name, text) in [
        (RUNNER_PATH, runner.as_str()),
        (HELPER_PATH, helper.as_str()),
    ] {
        for forbidden in ["rm -f", "rm -rf", "git clean", "git reset --hard"] {
            assert!(
                !text.contains(forbidden),
                "{name} must not contain destructive command {forbidden}"
            );
        }
    }
}

#[test]
fn helper_replays_contract_and_emits_e2e_artifacts() {
    let output_root = repo_path("target/memory_residency_replay_e2e_contract");
    let run_id = format!("contract-test-{}", std::process::id());
    let status = Command::new("python3")
        .arg(repo_path(HELPER_PATH))
        .arg("--contract")
        .arg(repo_path(CONTRACT_PATH))
        .arg("--output-root")
        .arg(&output_root)
        .arg("--run-id")
        .arg(&run_id)
        .arg("--generated-at")
        .arg("2026-06-13T00:00:00Z")
        .status()
        .expect("run memory residency replay helper");
    assert!(status.success(), "helper must replay the checked contract");

    let artifact_dir = output_root.join(format!("artifacts_{run_id}"));
    let summary: Value = serde_json::from_str(
        &fs::read_to_string(artifact_dir.join("summary.json")).expect("summary"),
    )
    .expect("summary json");
    let scenario_report: Value = serde_json::from_str(
        &fs::read_to_string(artifact_dir.join("scenario_report.json")).expect("scenario report"),
    )
    .expect("scenario report json");
    let events = fs::read_to_string(artifact_dir.join("events.ndjson")).expect("events");
    let operator_report =
        fs::read_to_string(artifact_dir.join("operator_report.md")).expect("operator report");

    assert_eq!(
        summary["schema_version"].as_str(),
        Some("e2e-suite-summary-v3")
    );
    assert_eq!(summary["status"].as_str(), Some("passed"));
    assert_eq!(summary["failed_count"].as_u64(), Some(0));
    assert_eq!(
        summary["copy_paste_rch_command"].as_str(),
        Some(string_field(&json(CONTRACT_PATH)["proof_lane"], "command"))
    );
    assert_eq!(
        scenario_report["schema_version"].as_str(),
        Some("memory-residency-replay-e2e-report-v1")
    );
    assert_eq!(scenario_report["scenario_count"].as_u64(), Some(6));
    assert_eq!(
        scenario_report["benchmark_evidence"]["included"].as_bool(),
        Some(false)
    );

    let event_lines = events.lines().collect::<Vec<_>>();
    assert_eq!(event_lines.len(), 6);
    for line in event_lines {
        let event: Value = serde_json::from_str(line).expect("event json");
        assert_eq!(
            event["schema_version"].as_str(),
            Some("memory-residency-replay-e2e-event-v1")
        );
        assert_eq!(event["status"].as_str(), Some("passed"));
    }
    assert!(operator_report.contains("No-Claim Boundaries"));
    assert!(operator_report.contains("fresh_topology_warm_evidence"));
}

#[test]
fn orchestrator_registers_memory_residency_replay_suite() {
    let orchestrator = read_repo_file(ORCHESTRATOR_PATH);
    for required in [
        "[memory-residency-replay]=\"run_memory_residency_replay_e2e.sh\"",
        "[memory-residency-replay]=\"target/e2e-results/memory_residency_replay_e2e\"",
        "[memory-residency-replay]=\"summary.json\"",
        "[memory-residency-replay]=\"artifacts_*\"",
        "[memory-residency-replay]=\"E2E-SUITE-MEMORY-RESIDENCY-REPLAY\"",
    ] {
        assert!(orchestrator.contains(required), "missing {required}");
    }
}

#[test]
fn proof_manifest_and_status_snapshot_map_replay_lane_without_overclaiming() {
    let manifest = json(MANIFEST_PATH);
    let status = json(STATUS_PATH);
    let contract = json(CONTRACT_PATH);
    let command = string_field(&contract["proof_lane"], "command");

    assert!(repo_path(POLICY_CONTRACT_PATH).exists());
    assert!(repo_path(ACCOUNTING_CONTRACT_PATH).exists());
    assert!(
        string_set(&manifest, "required_guarantee_ids")
            .contains("memory-residency-replay-e2e-contract")
    );

    let lane = find_by_id(
        array(&manifest, "lanes"),
        "lane_id",
        "memory-residency-replay-e2e-contract",
    );
    assert_eq!(lane["kind"].as_str(), Some("artifact_contract"));
    assert_eq!(
        lane["resource_envelope_class"].as_str(),
        Some("artifact-contract-medium")
    );
    assert_eq!(lane["command"].as_str(), Some(command));
    assert!(string_set(lane, "source_paths").contains(CONTRACT_PATH));
    assert!(string_set(lane, "source_paths").contains(RUNNER_PATH));
    assert!(string_set(lane, "source_paths").contains(DOCS_PATH));

    let guarantee = find_by_id(
        array(&manifest, "guarantees"),
        "guarantee_id",
        "memory-residency-replay-e2e-contract",
    );
    assert!(string_set(guarantee, "lane_ids").contains("memory-residency-replay-e2e-contract"));

    assert!(
        string_set(&status, "required_claim_categories")
            .contains("memory residency replay e2e contract")
    );
    let claim = find_by_id(
        array(&status, "claim_categories"),
        "claim_id",
        "memory-residency-replay-e2e-contract",
    );
    assert_eq!(
        claim["category"].as_str(),
        Some("memory residency replay e2e contract")
    );
    assert_eq!(claim["status"].as_str(), Some("yellow_scoped"));
    assert_eq!(
        claim["proof_evidence_status"].as_str(),
        Some("rerun-required")
    );
    assert!(claim["blocked_frontier"].is_null());
    assert!(
        string_set(claim, "manifest_lane_ids").contains("memory-residency-replay-e2e-contract")
    );
    assert_eq!(array(claim, "proof_commands")[0].as_str(), Some(command));
    let notes = string_field(claim, "notes");
    assert!(notes.contains("replay/e2e contract evidence only"));
    assert!(notes.contains("performance improvement"));
    assert!(notes.contains("broad workspace health"));
}
