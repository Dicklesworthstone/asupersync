#![allow(missing_docs)]

use asupersync::runtime::resource_monitor::{
    RUNTIME_PRESSURE_ADMISSION_DECISION_SCHEMA_VERSION,
    RUNTIME_PRESSURE_ADMISSION_POLICY_SCHEMA_VERSION,
    RUNTIME_PRESSURE_LAB_SCENARIO_EVIDENCE_SCHEMA_VERSION,
    RUNTIME_PRESSURE_RCH_PROOF_LANE_SCHEMA_VERSION,
    RUNTIME_PRESSURE_REGION_MEMORY_BUDGET_SCHEMA_VERSION, RUNTIME_PRESSURE_SNAPSHOT_SCHEMA_VERSION,
};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

const CONTRACT_PATH: &str = "artifacts/runtime_pressure_control_evidence_contract_v1.json";
const MANIFEST_PATH: &str = "artifacts/proof_lane_manifest_v1.json";
const README_PATH: &str = "README.md";
const RUNBOOK_PATH: &str = "docs/proof_runner_usage.md";
const OPERATOR_RUNBOOK_PATH: &str = "docs/runtime_pressure_triage_runbook.md";
const VERIFIER_PATH: &str = "tests/runtime_pressure_control_evidence_contract.rs";
const RCH_HEALTH_PATH: &str = "src/runtime/rch_health/mod.rs";
const PHASE6_CONTRACT_PATH: &str = "artifacts/phase6_methodology_gate_enforcement_contract_v1.json";
const PHASE6_VERIFIER_PATH: &str = "tests/phase6_methodology_gate_contract.rs";

fn repo_path(relative: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(relative)
}

fn read_repo_file(relative: &str) -> String {
    std::fs::read_to_string(repo_path(relative))
        .unwrap_or_else(|err| panic!("read {relative}: {err}"))
}

fn json(relative: &str) -> Value {
    serde_json::from_str(&read_repo_file(relative))
        .unwrap_or_else(|err| panic!("parse {relative}: {err}"))
}

fn array<'a>(value: &'a Value, key: &str) -> &'a Vec<Value> {
    value
        .get(key)
        .and_then(Value::as_array)
        .unwrap_or_else(|| panic!("{key} must be an array"))
}

fn bool_field(value: &Value, key: &str) -> bool {
    value
        .get(key)
        .and_then(Value::as_bool)
        .unwrap_or_else(|| panic!("{key} must be a bool"))
}

fn string<'a>(value: &'a Value, key: &str) -> &'a str {
    let text = value
        .get(key)
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("{key} must be a string"));
    assert!(!text.trim().is_empty(), "{key} must be nonempty");
    text
}

fn string_vec(value: &Value, key: &str) -> Vec<String> {
    array(value, key)
        .iter()
        .map(|item| {
            item.as_str()
                .unwrap_or_else(|| panic!("{key} entries must be strings"))
                .to_string()
        })
        .collect()
}

fn string_set(value: &Value, key: &str) -> BTreeSet<String> {
    string_vec(value, key).into_iter().collect()
}

fn manifest_lanes(manifest: &Value) -> BTreeMap<String, Value> {
    array(manifest, "lanes")
        .iter()
        .map(|lane| (string(lane, "lane_id").to_string(), lane.clone()))
        .collect()
}

fn manifest_guarantees(manifest: &Value) -> BTreeMap<String, Value> {
    array(manifest, "guarantees")
        .iter()
        .map(|guarantee| {
            (
                string(guarantee, "guarantee_id").to_string(),
                guarantee.clone(),
            )
        })
        .collect()
}

#[test]
fn contract_declares_schema_versions_sources_and_scope_policy() {
    let contract = json(CONTRACT_PATH);
    assert_eq!(
        contract.get("contract_version").and_then(Value::as_str),
        Some("runtime-pressure-control-evidence-contract-v1")
    );
    assert_eq!(
        contract.get("bead_id").and_then(Value::as_str),
        Some("asupersync-bwcdfl.4")
    );

    let source = contract
        .get("source_of_truth")
        .expect("source_of_truth object");
    assert_eq!(source["contract"].as_str(), Some(CONTRACT_PATH));
    assert_eq!(source["verifier"].as_str(), Some(VERIFIER_PATH));
    assert_eq!(source["proof_lane_manifest"].as_str(), Some(MANIFEST_PATH));
    assert_eq!(source["rch_health_source"].as_str(), Some(RCH_HEALTH_PATH));
    assert_eq!(source["readme"].as_str(), Some(README_PATH));
    assert_eq!(source["runbook"].as_str(), Some(RUNBOOK_PATH));
    assert_eq!(
        source["operator_runbook"].as_str(),
        Some(OPERATOR_RUNBOOK_PATH)
    );
    assert_eq!(
        source["phase6_gate_contract"].as_str(),
        Some(PHASE6_CONTRACT_PATH)
    );
    assert_eq!(
        source["phase6_gate_verifier"].as_str(),
        Some(PHASE6_VERIFIER_PATH)
    );

    let schemas = contract
        .get("schema_versions")
        .expect("schema_versions object");
    assert_eq!(
        schemas["runtime_pressure_snapshot"].as_str(),
        Some(RUNTIME_PRESSURE_SNAPSHOT_SCHEMA_VERSION)
    );
    assert_eq!(
        schemas["runtime_pressure_lab_scenario_evidence"].as_str(),
        Some(RUNTIME_PRESSURE_LAB_SCENARIO_EVIDENCE_SCHEMA_VERSION)
    );
    assert_eq!(
        schemas["runtime_pressure_admission_policy"].as_str(),
        Some(RUNTIME_PRESSURE_ADMISSION_POLICY_SCHEMA_VERSION)
    );
    assert_eq!(
        schemas["runtime_pressure_admission_decision"].as_str(),
        Some(RUNTIME_PRESSURE_ADMISSION_DECISION_SCHEMA_VERSION)
    );
    assert_eq!(
        schemas["runtime_pressure_region_memory_budget"].as_str(),
        Some(RUNTIME_PRESSURE_REGION_MEMORY_BUDGET_SCHEMA_VERSION)
    );
    assert_eq!(
        schemas["runtime_pressure_rch_proof_lane"].as_str(),
        Some(RUNTIME_PRESSURE_RCH_PROOF_LANE_SCHEMA_VERSION)
    );

    let policy = contract
        .get("operator_policy")
        .expect("operator_policy object");
    assert!(bool_field(
        policy,
        "production_signals_are_advisory_without_lab_or_replay_evidence"
    ));
    assert!(bool_field(
        policy,
        "adaptive_controls_remain_opt_in_until_stronger_evidence"
    ));
    assert!(!bool_field(
        policy,
        "lab_scenarios_are_real_host_throughput_proof"
    ));
    assert!(bool_field(
        policy,
        "deadlock_claims_require_explicit_trapped_cycle_proof"
    ));
}

#[test]
fn contract_declares_no_local_rch_fallback_evidence() {
    let contract = json(CONTRACT_PATH);
    let evidence = contract
        .get("no_local_rch_fallback_evidence")
        .expect("no_local_rch_fallback_evidence object");

    assert_eq!(
        string(evidence, "evidence_id"),
        "pressure-proof-no-local-rch-fallback"
    );
    assert_eq!(string(evidence, "bead_id"), "asupersync-bwcdfl.10");
    assert_eq!(
        string_set(evidence, "applies_to_lanes"),
        BTreeSet::from(["runtime-pressure-control-evidence-contract".to_string()])
    );
    assert_eq!(
        string(evidence, "remote_execution_command_prefix"),
        "RCH_REQUIRE_REMOTE=1 rch exec -- "
    );
    assert_eq!(
        string_set(evidence, "required_command_markers"),
        BTreeSet::from([
            "RCH_REQUIRE_REMOTE=1".to_string(),
            "rch exec -- env".to_string(),
            "CARGO_TARGET_DIR=".to_string(),
            "cargo test -p asupersync --test runtime_pressure_control_evidence_contract"
                .to_string(),
        ])
    );
    assert_eq!(
        string_set(evidence, "remote_transcript_success_markers"),
        BTreeSet::from([
            "Selected worker:".to_string(),
            "Executing command remotely:".to_string(),
            "Remote command finished: exit=0".to_string(),
            "[RCH] remote".to_string(),
        ])
    );
    assert_eq!(
        string_set(evidence, "forbidden_transcript_markers"),
        BTreeSet::from([
            "[RCH] local".to_string(),
            "Executing command locally".to_string(),
            "local fallback accepted".to_string(),
        ])
    );
    assert_eq!(string(evidence, "receipt_source"), RCH_HEALTH_PATH);

    let fields = evidence
        .get("receipt_required_fields")
        .expect("receipt_required_fields object");
    assert!(bool_field(fields, "remote_required"));
    assert!(!bool_field(fields, "local_fallback_allowed"));
    assert_eq!(string(fields, "refusal_code"), "local_fallback_refused");
    assert_eq!(
        string_set(fields, "reason_codes"),
        BTreeSet::from([
            "remote_required".to_string(),
            "local_fallback_refused".to_string(),
        ])
    );

    let closeout_rule = string(evidence, "closeout_rule");
    for required in [
        "remote-required prefix",
        "CARGO_TARGET_DIR",
        "saved transcript",
        "admission receipt",
        "local Cargo fallback",
    ] {
        assert!(
            closeout_rule.contains(required),
            "closeout rule must contain {required:?}"
        );
    }

    let non_claims = string_vec(evidence, "does_not_prove")
        .join("\n")
        .to_ascii_lowercase();
    for required in [
        "rch fleet",
        "real-host throughput",
        "production admission control",
        "scheduler performance",
    ] {
        assert!(
            non_claims.contains(required),
            "fallback evidence must preserve non-claim phrase {required:?}"
        );
    }

    let rch_health = read_repo_file(RCH_HEALTH_PATH);
    for required in [
        "LocalFallbackRefused",
        "local_fallback_refused",
        "local_fallback_allowed",
        "remote_required",
        "remote-required proof refused local Cargo fallback",
        "RchWorkerAdmissionScheduleRow",
    ] {
        assert!(
            rch_health.contains(required),
            "{RCH_HEALTH_PATH} must contain {required:?}"
        );
    }
}

#[test]
fn contract_declares_operator_diagnostics_bundle() {
    let contract = json(CONTRACT_PATH);
    let bundle = contract
        .get("operator_diagnostics_bundle")
        .expect("operator_diagnostics_bundle object");

    assert_eq!(
        string(bundle, "bundle_id"),
        "pressure-control-operator-diagnostics-bundle"
    );
    assert_eq!(string(bundle, "bead_id"), "asupersync-bwcdfl.11");
    assert_eq!(string(bundle, "operator_doc"), OPERATOR_RUNBOOK_PATH);
    let purpose = string(bundle, "purpose");
    for required in [
        "snapshot verdicts",
        "admission decisions",
        "region memory-budget pressure",
        "RCH proof-lane pressure",
        "deterministic replay evidence",
        "validation fallback status",
        "scope limits",
    ] {
        assert!(
            purpose.contains(required),
            "diagnostics bundle purpose must contain {required:?}"
        );
    }

    assert_eq!(
        string_vec(bundle, "ordered_sections"),
        vec![
            "snapshot_verdict".to_string(),
            "admission_decision".to_string(),
            "region_memory_budget_pressure".to_string(),
            "rch_proof_lane_pressure".to_string(),
            "deterministic_replay_evidence".to_string(),
            "validation_fallback_status".to_string(),
            "scope_non_claims".to_string(),
        ]
    );
    assert_eq!(
        string_set(bundle, "required_evidence_markers"),
        BTreeSet::from([
            "RuntimePressureSnapshot.overall_verdict".to_string(),
            "RuntimePressureAdmissionDecision".to_string(),
            "RuntimePressureRegionMemoryBudgetSnapshot".to_string(),
            "RuntimePressureRchProofLaneSnapshot".to_string(),
            "RuntimePressureLabScenarioEvidence".to_string(),
            "no-local-RCH fallback evidence".to_string(),
            "scheduler_tail_pressure".to_string(),
            "spectral_recommendations".to_string(),
        ])
    );

    let status_meanings = array(bundle, "status_semantics")
        .iter()
        .map(|status| {
            (
                string(status, "status").to_string(),
                string(status, "meaning").to_string(),
            )
        })
        .collect::<BTreeMap<_, _>>();
    assert_eq!(
        status_meanings.keys().cloned().collect::<BTreeSet<_>>(),
        BTreeSet::from([
            "advisory".to_string(),
            "replay_backed".to_string(),
            "trapped_cycle_proven".to_string(),
            "validation_blocked".to_string(),
        ])
    );
    for required in [
        "does not by itself prove throughput",
        "deterministic lab or replay evidence",
        "spectral fragmentation alone is insufficient",
        "name the first blocker",
    ] {
        assert!(
            status_meanings
                .values()
                .any(|meaning| meaning.contains(required)),
            "diagnostics bundle status meanings must contain {required:?}"
        );
    }

    let closeout_rule = string(bundle, "closeout_rule");
    for required in [
        "diagnostics bundle status",
        "strongest evidence class",
        "non-claim",
        "policy or scheduler follow-up",
    ] {
        assert!(
            closeout_rule.contains(required),
            "diagnostics closeout rule must contain {required:?}"
        );
    }

    let non_claims = string_vec(bundle, "does_not_prove")
        .join("\n")
        .to_ascii_lowercase();
    for required in [
        "real-host throughput",
        "scheduler performance",
        "production-on-by-default",
        "per-region allocator enforcement",
        "trapped-cycle proof",
    ] {
        assert!(
            non_claims.contains(required),
            "diagnostics bundle must preserve non-claim phrase {required:?}"
        );
    }
}

#[test]
fn contract_declares_scheduler_pressure_flamegraph_attribution() {
    let contract = json(CONTRACT_PATH);
    let attribution = contract
        .get("scheduler_pressure_flamegraph_attribution")
        .expect("scheduler_pressure_flamegraph_attribution object");

    assert_eq!(string(attribution, "phase6_gate_id"), "flamegraph");
    assert_eq!(string(attribution, "phase6_contract"), PHASE6_CONTRACT_PATH);
    assert_eq!(string(attribution, "phase6_verifier"), PHASE6_VERIFIER_PATH);
    assert_eq!(
        string(attribution, "scheduler_pressure_signal"),
        "scheduler_tail_pressure"
    );
    assert_eq!(
        string(attribution, "lab_scenario_family"),
        "cpu_lane_pressure"
    );
    assert_eq!(
        string(attribution, "artifact_path_pattern"),
        "artifacts/flamegraphs/main-<bead-or-short-sha>.svg"
    );
    assert_eq!(
        string(attribution, "benchmark_surface"),
        "methodology_baselines"
    );
    assert_eq!(
        string_set(attribution, "benchmark_rows"),
        BTreeSet::from([
            "methodology/task_spawn/inject_ready_global_queue".to_string(),
            "methodology/task_spawn/local_queue_push".to_string(),
            "methodology/task_spawn/local_queue_spawn_batch/1000".to_string(),
        ])
    );

    let combined_non_claims = string_vec(attribution, "does_not_support")
        .join("\n")
        .to_ascii_lowercase();
    for required in [
        "does not prove",
        "performance improvement",
        "real-host throughput",
        "scheduler regressions",
    ] {
        assert!(
            combined_non_claims.contains(required),
            "attribution must preserve non-claim phrase {required:?}"
        );
    }

    let phase6 = json(PHASE6_CONTRACT_PATH);
    let flamegraph_gate = array(&phase6, "direct_main_local_gates")
        .iter()
        .find(|gate| gate["gate_id"].as_str() == Some("flamegraph"))
        .expect("phase6 flamegraph gate");
    let pressure_attribution = flamegraph_gate
        .get("pressure_control_attribution")
        .expect("pressure_control_attribution object");
    assert_eq!(string(pressure_attribution, "contract"), CONTRACT_PATH);
    assert_eq!(
        string(pressure_attribution, "signal"),
        "scheduler_tail_pressure"
    );
    assert_eq!(
        string(pressure_attribution, "operator_runbook"),
        OPERATOR_RUNBOOK_PATH
    );
}

#[test]
fn contract_scenario_families_match_runtime_lab_evidence_surface() {
    let contract = json(CONTRACT_PATH);
    let scenarios = array(&contract, "scenario_families");
    let actual = scenarios
        .iter()
        .map(|scenario| {
            (
                string(scenario, "scenario_kind").to_string(),
                string(scenario, "expected_verdict").to_string(),
                string_set(scenario, "diagnostic_labels"),
            )
        })
        .collect::<Vec<_>>();

    let expected = vec![
        (
            "healthy".to_string(),
            "healthy".to_string(),
            BTreeSet::from(["all_signals_present".to_string()]),
        ),
        (
            "cpu_lane_pressure".to_string(),
            "critical".to_string(),
            BTreeSet::from([
                "cpu_load_hard_limit".to_string(),
                "resource_heavy_degradation".to_string(),
                "scheduler_tail_pressure".to_string(),
            ]),
        ),
        (
            "resource_fallback_degraded".to_string(),
            "degraded".to_string(),
            BTreeSet::from([
                "memory_soft_pressure".to_string(),
                "platform_probe_fallback".to_string(),
            ]),
        ),
        (
            "region_memory_budget_overrun".to_string(),
            "critical".to_string(),
            BTreeSet::from([
                "region_memory_budget_advisory".to_string(),
                "region_memory_budget_exhausted".to_string(),
            ]),
        ),
        (
            "structural_warning".to_string(),
            "critical".to_string(),
            BTreeSet::from([
                "spectral_fragmented_topology".to_string(),
                "trapped_cycle_detection_required".to_string(),
            ]),
        ),
        (
            "rch_proof_lane_remote_refusal".to_string(),
            "critical".to_string(),
            BTreeSet::from([
                "local_fallback_refused".to_string(),
                "rch_remote_required_refused".to_string(),
            ]),
        ),
    ];

    assert_eq!(actual, expected);
}

#[test]
fn contract_claims_do_not_overstate_pressure_control_evidence() {
    let contract = json(CONTRACT_PATH);
    let claims = array(&contract, "evidence_claims");
    let claim_ids = claims
        .iter()
        .map(|claim| string(claim, "claim_id").to_string())
        .collect::<BTreeSet<_>>();
    assert_eq!(
        claim_ids,
        BTreeSet::from([
            "deterministic-lab-scenario-classification".to_string(),
            "opt-in-pressure-admission-policy".to_string(),
            "operator-diagnostics-bundle".to_string(),
            "operator-pressure-snapshot-schema".to_string(),
            "rch-proof-lane-pressure-signal".to_string(),
            "rch-no-local-fallback-evidence".to_string(),
            "region-memory-budget-pressure-signal".to_string(),
            "scheduler-pressure-flamegraph-attribution".to_string(),
            "spectral-deadlock-scope-limit".to_string(),
        ])
    );

    for claim in claims {
        let claim_id = string(claim, "claim_id");
        assert!(
            !array(claim, "proves").is_empty(),
            "{claim_id}: proves must be nonempty"
        );
        assert!(
            !array(claim, "does_not_prove").is_empty(),
            "{claim_id}: does_not_prove must be nonempty"
        );
        assert!(
            !array(claim, "requires_additional_proof_for").is_empty(),
            "{claim_id}: requires_additional_proof_for must be nonempty"
        );
    }

    let combined_non_claims = claims
        .iter()
        .flat_map(|claim| string_vec(claim, "does_not_prove"))
        .collect::<Vec<_>>()
        .join("\n")
        .to_ascii_lowercase();
    for required_phrase in [
        "real-host throughput",
        "admission control",
        "not a deadlock proof",
    ] {
        assert!(
            combined_non_claims.contains(required_phrase),
            "pressure contract must preserve non-claim phrase {required_phrase:?}"
        );
    }
}

#[test]
fn proof_lane_manifest_maps_pressure_contract_lane() {
    let contract = json(CONTRACT_PATH);
    let manifest = json(MANIFEST_PATH);
    let lanes = manifest_lanes(&manifest);
    let guarantees = manifest_guarantees(&manifest);
    let contract_lane = array(&contract, "proof_lanes")
        .first()
        .expect("pressure contract must declare one proof lane");
    let lane_id = string(contract_lane, "lane_id");
    let guarantee_id = string(contract_lane, "manifest_guarantee_id");
    let command = string(contract_lane, "command");

    let lane = lanes
        .get(lane_id)
        .unwrap_or_else(|| panic!("manifest missing lane {lane_id}"));
    assert_eq!(string(lane, "command"), command);
    assert_eq!(string(lane, "kind"), "artifact_contract");
    assert_eq!(
        string_set(lane, "guarantee_ids"),
        BTreeSet::from([guarantee_id.to_string()])
    );
    assert_eq!(
        string_set(lane, "source_paths"),
        BTreeSet::from([
            CONTRACT_PATH.to_string(),
            OPERATOR_RUNBOOK_PATH.to_string(),
            PHASE6_CONTRACT_PATH.to_string(),
            PHASE6_VERIFIER_PATH.to_string(),
            README_PATH.to_string(),
            RCH_HEALTH_PATH.to_string(),
            RUNBOOK_PATH.to_string(),
            "src/runtime/resource_monitor.rs".to_string(),
            VERIFIER_PATH.to_string(),
        ])
    );
    assert!(
        string(lane, "explicit_not_covered").contains("real-host throughput"),
        "{lane_id}: manifest lane must preserve throughput non-claim"
    );
    assert!(
        string(lane, "covers").contains("no-local-RCH fallback evidence"),
        "{lane_id}: manifest lane must name no-local-RCH fallback evidence"
    );
    assert!(
        string(lane, "covers").contains("operator diagnostics bundle"),
        "{lane_id}: manifest lane must name operator diagnostics bundle"
    );
    assert!(
        string(lane, "explicit_not_covered").contains("RCH fleet availability"),
        "{lane_id}: manifest lane must preserve RCH fleet non-claim"
    );
    assert!(
        command.starts_with("RCH_REQUIRE_REMOTE=1 rch exec -- "),
        "{lane_id}: command must require remote rch execution"
    );
    assert!(
        command.contains("CARGO_TARGET_DIR="),
        "{lane_id}: command must isolate target output"
    );
    assert!(
        command.contains("runtime_pressure_control_evidence_contract"),
        "{lane_id}: command must run this verifier"
    );

    let guarantee = guarantees
        .get(guarantee_id)
        .unwrap_or_else(|| panic!("manifest missing guarantee {guarantee_id}"));
    assert_eq!(
        string_set(guarantee, "lane_ids"),
        BTreeSet::from([lane_id.to_string()])
    );
}

#[test]
fn docs_reference_pressure_contract_and_verifier_markers() {
    let contract = json(CONTRACT_PATH);
    let docs = contract
        .get("documentation_contract")
        .expect("documentation_contract object");
    let marker = string(docs, "required_marker");
    let verifier = string(docs, "verifier_marker");

    for path in string_vec(docs, "docs_must_reference_contract") {
        let text = read_repo_file(&path);
        assert!(text.contains(marker), "{path} must reference {marker}");
        assert!(text.contains(verifier), "{path} must reference {verifier}");
    }
}

#[test]
fn operator_runbook_preserves_pressure_triage_and_replay_markers() {
    let text = read_repo_file(OPERATOR_RUNBOOK_PATH);
    for required in [
        CONTRACT_PATH,
        VERIFIER_PATH,
        "runtime-pressure-control-evidence-contract",
        "RuntimePressureSnapshot.overall_verdict",
        "RuntimePressureAdmissionDecision",
        "RuntimePressureLabScenarioEvidence",
        "RuntimePressureRegionMemoryBudgetSnapshot",
        "RuntimePressureRchProofLaneSnapshot",
        "Pressure-Control Diagnostics Bundle",
        "operator_diagnostics_bundle",
        "snapshot_verdict",
        "admission_decision",
        "region_memory_budget_pressure",
        "rch_proof_lane_pressure",
        "deterministic_replay_evidence",
        "validation_fallback_status",
        "scope_non_claims",
        "advisory",
        "replay_backed",
        "trapped_cycle_proven",
        "validation_blocked",
        "no-local-RCH fallback evidence",
        "Selected worker:",
        "Executing command remotely:",
        "Remote command finished: exit=0",
        "[RCH] remote",
        "[RCH] local",
        "local_fallback_refused",
        "remote_required=true",
        "local_fallback_allowed=false",
        "scheduler_tail_pressure",
        "artifacts/flamegraphs/main-<bead-or-short-sha>.svg",
        "artifacts/phase6_methodology_gate_enforcement_contract_v1.json",
        "methodology/task_spawn/inject_ready_global_queue",
        "methodology/task_spawn/local_queue_push",
        "region_memory_budgets",
        "trapped-cycle proof",
        "local Cargo fallback",
        "RCH_REQUIRE_REMOTE=1 rch exec --",
        "cargo test -p asupersync --test runtime_pressure_control_evidence_contract",
        "cargo test -p asupersync --test proof_lane_manifest_contract",
        "Optional work fails closed for unknown pressure snapshot schemas",
    ] {
        assert!(
            text.contains(required),
            "{OPERATOR_RUNBOOK_PATH} must contain {required:?}"
        );
    }

    for scenario in [
        "healthy",
        "cpu_lane_pressure",
        "resource_fallback_degraded",
        "region_memory_budget_overrun",
        "rch_proof_lane_remote_refusal",
        "structural_warning",
    ] {
        assert!(
            text.contains(scenario),
            "{OPERATOR_RUNBOOK_PATH} must name scenario {scenario:?}"
        );
    }
}

#[test]
fn proof_runner_docs_preserve_no_local_rch_fallback_markers() {
    let text = read_repo_file(RUNBOOK_PATH);
    for required in [
        CONTRACT_PATH,
        VERIFIER_PATH,
        "Pressure-Control RCH Fallback Evidence",
        "RCH_REQUIRE_REMOTE=1 rch exec -- ",
        "rch exec -- env",
        "CARGO_TARGET_DIR=",
        "Selected worker:",
        "Executing command remotely:",
        "Remote command finished: exit=0",
        "[RCH] remote",
        "[RCH] local",
        "Executing command locally",
        "local fallback accepted",
        "remote_required=true",
        "local_fallback_allowed=false",
        "refusal_code=local_fallback_refused",
        "reason_codes",
        "real-host throughput",
        "scheduler performance",
    ] {
        assert!(
            text.contains(required),
            "{RUNBOOK_PATH} must contain {required:?}"
        );
    }
}
