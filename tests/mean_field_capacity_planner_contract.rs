//! Contract-backed proofs for the mean-field capacity planner.

use asupersync::runtime::config::{
    CapacityEnvelopeBrownoutStage, CapacityEnvelopeBudget, CapacityEnvelopeCalibrationStatus,
    CapacityEnvelopeEvidenceSnapshot, CapacityEnvelopeHostFingerprint,
    CapacityEnvelopePlannerRequest, CoordinationWorkloadExpansionEvidence,
    CoordinationWorkloadRedactionStatus, CoordinationWorkloadTrustStatus,
    HostProfileEvidenceArtifact, HostProfileEvidenceCalibrationStatus, HostProfileEvidenceSet,
    HostProfileHostResources, HostProfileId, HostProfileManualOverrides,
    HostProfilePlannerObjective, MEAN_FIELD_CAPACITY_PLANNER_REPORT_SCHEMA_VERSION,
    MeanFieldCapacityPlan, MeanFieldCapacityPlannerRequest, MeanFieldCapacityPlannerVerdict,
    MeanFieldWorkloadMix, RuntimeConfig,
};
use serde::Deserialize;
use serde_json::{Value, json};
use std::fs;
use std::path::Path;
use std::process::Command;

const DEFAULT_SCENARIO_ID: &str = "AA-MEAN-FIELD-CAPACITY-PLANNER-64C-256G";
const RUNNER_PATH: &str = "scripts/run_mean_field_capacity_planner_smoke.sh";
const CAPACITY_CERT_HASH: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

#[derive(Debug, Deserialize)]
struct MeanFieldContract {
    contract_version: String,
    smoke_scenarios: Vec<MeanFieldScenario>,
}

#[derive(Debug, Deserialize)]
struct MeanFieldScenario {
    scenario_id: String,
    expected_verdict: String,
}

fn contract() -> MeanFieldContract {
    serde_json::from_str(include_str!(
        "../artifacts/mean_field_capacity_planner_smoke_contract_v1.json"
    ))
    .expect("mean-field capacity planner contract must parse")
}

fn proof_artifact(kind: &str) -> HostProfileEvidenceArtifact {
    HostProfileEvidenceArtifact {
        artifact_id: format!("artifacts/{kind}_smoke_contract_v1.json"),
        contract_version: format!("{kind}-smoke-contract-v1"),
        validation_passed: true,
        confidence_percent: 94,
        calibration_status: HostProfileEvidenceCalibrationStatus::Current,
    }
}

fn controller_evidence() -> HostProfileEvidenceSet {
    HostProfileEvidenceSet {
        brownout: Some(proof_artifact("overload_brownout")),
        otlp_brownout: Some(proof_artifact("otlp_brownout_shedding")),
        admission_steering: Some(proof_artifact("cohort_admission_steering")),
        adaptive_batch_sizing: Some(proof_artifact("adaptive_batch_sizing")),
        blocking_pool_affinity: Some(proof_artifact("blocking_pool_affinity")),
        trace_storage_profile: Some(proof_artifact("trace_storage_profile")),
        coordination_workload_expansion: Some(CoordinationWorkloadExpansionEvidence {
            artifact_id: "artifacts/coordination_workload_bridge_smoke_contract_v1.json"
                .to_string(),
            contract_version: "coordination-workload-bridge-smoke-contract-v1".to_string(),
            pack_hash: "sha256:coordination-pack-64c-256g".to_string(),
            source_bundle_hash: "sha256:coordination-source-64c-256g".to_string(),
            validation_passed: true,
            redaction_status: CoordinationWorkloadRedactionStatus::Passed,
            trust_status: CoordinationWorkloadTrustStatus::Trusted,
            sample_count: 96,
            artifact_age_hours: 6,
            host_fingerprint: host_fingerprint(),
            pressure_basis_points: 12_000,
        }),
    }
}

fn host_resources() -> HostProfileHostResources {
    HostProfileHostResources {
        cpu_cores: 64,
        memory_gib: 256,
    }
}

fn host_fingerprint() -> CapacityEnvelopeHostFingerprint {
    CapacityEnvelopeHostFingerprint {
        hostname: "lab-64c-256g-a".to_string(),
        arch: "x86_64".to_string(),
        cpu_cores: 64,
        memory_gib: 256,
    }
}

fn evidence_snapshot() -> CapacityEnvelopeEvidenceSnapshot {
    CapacityEnvelopeEvidenceSnapshot {
        scenario_artifact_id: "artifacts/swarm_scenario_locality_64c_256g.json".to_string(),
        scenario_artifact_hash: "a74fd668c2b7d26ef6f7872f0d1048349f8d618fc79a4f8a01273f93be1f7b21"
            .to_string(),
        scenario_contract_version: "swarm-scenario-evidence-v1".to_string(),
        sample_count: 96,
        calibration_status: CapacityEnvelopeCalibrationStatus::Calibrated,
        host_fingerprint: host_fingerprint(),
        artifact_age_hours: 12,
        measured_worker_count: 64,
        measured_agent_count: 384,
        measured_queue_depth: 28_000,
        throughput_ops_per_sec: 248_000,
        wake_to_run_p50_ns: 220_000,
        wake_to_run_p95_ns: 640_000,
        wake_to_run_p99_ns: 900_000,
        cancellation_debt_units: 96,
        memory_pressure_basis_points: 5_100,
        brownout_stage: CapacityEnvelopeBrownoutStage::OptionalFirst,
        brownout_risk_basis_points: 550,
        retention_budget_gib: 2,
    }
}

fn capacity_request() -> CapacityEnvelopePlannerRequest {
    CapacityEnvelopePlannerRequest {
        objective: HostProfilePlannerObjective::LocalityFirst,
        requested_profile: Some(HostProfileId::LocalityFirst64C256G),
        host_resources: host_resources(),
        controller_evidence: controller_evidence(),
        manual_overrides: HostProfileManualOverrides::default(),
        host_fingerprint: host_fingerprint(),
        evidence_snapshot: evidence_snapshot(),
        candidate_worker_counts: vec![48, 56, 64],
        candidate_agent_counts: vec![256, 384, 512],
        budget: CapacityEnvelopeBudget::default(),
        budget_overrides: Default::default(),
        environment_note: Some("ticket=OPS-CAP api_token=redacted".to_string()),
        validation_command: Some("rch exec -- cargo test capacity".to_string()),
    }
}

fn planner_request() -> MeanFieldCapacityPlannerRequest {
    MeanFieldCapacityPlannerRequest {
        enabled: true,
        objective: HostProfilePlannerObjective::LocalityFirst,
        host_resources: host_resources(),
        host_fingerprint: host_fingerprint(),
        workload_mix: MeanFieldWorkloadMix::balanced(),
        capacity_certificate: capacity_request().plan(),
        evidence_confidence_percent: 93,
        capacity_certificate_id: "artifacts/capacity_envelope_planner_smoke_contract_v1.json"
            .to_string(),
        capacity_certificate_hash: CAPACITY_CERT_HASH.to_string(),
        replay_command:
            "rch exec -- cargo test -p asupersync --test mean_field_capacity_planner_contract"
                .to_string(),
    }
}

fn plan_report_json(plan: &MeanFieldCapacityPlan, scenario_id: &str) -> Value {
    json!({
        "schema_version": plan.schema_version,
        "scenario_id": scenario_id,
        "verdict": plan.verdict.as_str(),
        "host_fingerprint_class": plan.host_fingerprint_class,
        "cpu_bucket": plan.cpu_bucket,
        "memory_bucket": plan.memory_bucket,
        "workload_mix": {
            "coordination_basis_points": plan.workload_mix.coordination_basis_points,
            "io_basis_points": plan.workload_mix.io_basis_points,
            "cpu_basis_points": plan.workload_mix.cpu_basis_points,
            "evidence_basis_points": plan.workload_mix.evidence_basis_points,
            "background_basis_points": plan.workload_mix.background_basis_points,
            "dominant_class": plan.dominant_workload_class,
        },
        "recommended_profile": plan.selected_profile.as_str(),
        "fallback_profile": plan.fallback_profile.as_str(),
        "recommended_agent_ceiling": plan.recommended_agent_ceiling,
        "recommended_worker_threads": plan.recommended_worker_threads,
        "recommended_global_queue_limit": plan.recommended_global_queue_limit,
        "recommended_capacity_hints": {
            "task_capacity": plan.recommended_capacity_hints.task_capacity,
            "region_capacity": plan.recommended_capacity_hints.region_capacity,
            "obligation_capacity": plan.recommended_capacity_hints.obligation_capacity,
        },
        "recommended_trace_storage_profile": plan.recommended_trace_storage_profile.as_str(),
        "recommended_arena_temperature_policy": plan.recommended_arena_temperature_policy.as_str(),
        "recommended_bundle_digest": plan.recommended_bundle_digest,
        "confidence_percent": plan.confidence_percent,
        "certificate_refs": plan.certificate_refs.iter().map(|reference| {
            json!({
                "artifact_id": reference.artifact_id,
                "digest": reference.digest,
                "role": reference.role,
            })
        }).collect::<Vec<_>>(),
        "controller_settings": plan.controller_settings.iter().map(|setting| {
            json!({
                "controller": setting.controller,
                "setting": setting.setting,
                "source": setting.source,
            })
        }).collect::<Vec<_>>(),
        "refusal_reasons": plan.refusal_reasons,
        "no_win": plan.no_win,
        "replay_command": plan.replay_command,
    })
}

#[test]
fn mean_field_planner_recommends_certificate_backed_large_host_settings() {
    let plan = planner_request().plan();

    assert!(plan.recommended());
    assert_eq!(plan.verdict, MeanFieldCapacityPlannerVerdict::Recommended);
    assert_eq!(plan.selected_profile, HostProfileId::LocalityFirst64C256G);
    assert_eq!(plan.host_fingerprint_class, "cpu_64_plus_mem_256_plus");
    assert_eq!(plan.cpu_bucket, "cpu_64_plus");
    assert_eq!(plan.memory_bucket, "mem_256_plus");
    assert!(plan.recommended_agent_ceiling <= 512);
    assert!(plan.recommended_worker_threads <= 64);
    assert!(plan.recommended_capacity_hints.task_capacity >= 512);
    assert!(!plan.certificate_refs.is_empty());
    assert!(plan.refusal_reasons.is_empty());
    assert!(!plan.no_win);
}

#[test]
fn mean_field_planner_fails_closed_for_unsupported_topology() {
    let mut request = planner_request();
    request.host_resources = HostProfileHostResources {
        cpu_cores: 32,
        memory_gib: 128,
    };
    request.host_fingerprint = CapacityEnvelopeHostFingerprint {
        hostname: "small-host".to_string(),
        arch: "x86_64".to_string(),
        cpu_cores: 32,
        memory_gib: 128,
    };

    let plan = request.plan();

    assert_eq!(plan.verdict, MeanFieldCapacityPlannerVerdict::FailClosed);
    assert!(
        plan.refusal_reasons
            .iter()
            .any(|reason| reason.contains("unsupported topology"))
    );
}

#[test]
fn mean_field_planner_uses_no_win_for_low_confidence_evidence() {
    let mut request = planner_request();
    request.evidence_confidence_percent = 60;

    let plan = request.plan();

    assert_eq!(plan.verdict, MeanFieldCapacityPlannerVerdict::NoWin);
    assert_eq!(plan.selected_profile, HostProfileId::ConservativeBaseline);
    assert!(plan.no_win);
    assert!(
        plan.refusal_reasons
            .iter()
            .any(|reason| reason.contains("evidence_confidence_percent"))
    );
}

#[test]
fn mean_field_planner_uses_no_win_for_conflicting_controller_goals() {
    let mut request = planner_request();
    request.objective = HostProfilePlannerObjective::EvidenceRetentionFirst;
    request.workload_mix = MeanFieldWorkloadMix::new(4_500, 2_000, 1_500, 1_000, 1_000);

    let plan = request.plan();

    assert_eq!(plan.verdict, MeanFieldCapacityPlannerVerdict::NoWin);
    assert!(plan.no_win);
    assert!(
        plan.refusal_reasons
            .iter()
            .any(|reason| reason.contains("conflicting_goals"))
    );
}

#[test]
fn mean_field_planner_fails_closed_for_invalid_workload_mix() {
    let mut request = planner_request();
    request.workload_mix = MeanFieldWorkloadMix::new(4_000, 4_000, 4_000, 0, 0);

    let plan = request.plan();

    assert_eq!(plan.verdict, MeanFieldCapacityPlannerVerdict::FailClosed);
    assert!(
        plan.refusal_reasons
            .iter()
            .any(|reason| reason.contains("workload mix must sum"))
    );
}

#[test]
fn mean_field_planner_disabled_mode_matches_conservative_baseline() {
    let mut request = planner_request();
    request.enabled = false;

    let plan = request.plan();
    let baseline = RuntimeConfig::default();

    assert_eq!(plan.verdict, MeanFieldCapacityPlannerVerdict::Disabled);
    assert_eq!(plan.selected_profile, HostProfileId::ConservativeBaseline);
    assert_eq!(plan.recommended_worker_threads, baseline.worker_threads);
    assert_eq!(
        plan.recommended_global_queue_limit,
        baseline.global_queue_limit
    );
    assert_eq!(
        plan.recommended_capacity_hints,
        baseline.resolved_capacity_hints()
    );
}

#[test]
fn mean_field_capacity_planner_smoke_emits_report() {
    let contract = contract();
    assert_eq!(
        contract.contract_version,
        "mean-field-capacity-planner-smoke-contract-v1"
    );
    let scenario = contract
        .smoke_scenarios
        .iter()
        .find(|scenario| scenario.scenario_id == DEFAULT_SCENARIO_ID)
        .expect("default mean-field scenario");
    let plan = planner_request().plan();
    assert_eq!(plan.verdict.as_str(), scenario.expected_verdict);

    let report = plan_report_json(&plan, &scenario.scenario_id);
    assert_eq!(
        report["schema_version"],
        json!(MEAN_FIELD_CAPACITY_PLANNER_REPORT_SCHEMA_VERSION)
    );
    assert_eq!(
        report["host_fingerprint_class"],
        json!("cpu_64_plus_mem_256_plus")
    );
    assert!(report["certificate_refs"].as_array().expect("refs").len() >= 2);
    assert!(
        report["controller_settings"]
            .as_array()
            .expect("settings")
            .iter()
            .any(|row| row["controller"] == "arena_capacity")
    );
    assert!(
        report["replay_command"]
            .as_str()
            .expect("replay")
            .contains("rch exec")
    );

    if let Ok(path) = std::env::var("ASUPERSYNC_MEAN_FIELD_CAPACITY_PLANNER_REPORT_PATH") {
        let compact_report = serde_json::to_string(&report).expect("report renders compactly");
        println!("ASUPERSYNC_MEAN_FIELD_CAPACITY_PLANNER_REPORT_JSON={compact_report}");
        if let Some(parent) = Path::new(&path).parent() {
            fs::create_dir_all(parent).expect("report parent directory exists");
        }
        fs::write(
            path,
            serde_json::to_string_pretty(&report).expect("report renders"),
        )
        .expect("report writes");
    }
}

#[test]
fn mean_field_runner_dry_run_records_rch_plan() {
    let repo_root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let output_root = tempfile::tempdir().expect("temp output root");
    let output_root_path = output_root.path().to_string_lossy().into_owned();
    let output = Command::new("bash")
        .current_dir(repo_root)
        .arg(RUNNER_PATH)
        .arg("--dry-run")
        .arg("--run-id")
        .arg("dry-run-smoke")
        .arg("--output-root")
        .arg(&output_root_path)
        .output()
        .expect("run mean-field dry-run");

    assert!(
        output.status.success(),
        "dry-run runner failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let run_dir = output_root
        .path()
        .join("run_dry-run-smoke")
        .join(DEFAULT_SCENARIO_ID);
    let report_path = run_dir.join("run_report.json");
    let log_path = run_dir.join("run.log");
    let report: Value = serde_json::from_str(
        &fs::read_to_string(&report_path)
            .unwrap_or_else(|_| panic!("missing {}", report_path.display())),
    )
    .expect("valid dry-run report json");
    let log =
        fs::read_to_string(&log_path).unwrap_or_else(|_| panic!("missing {}", log_path.display()));
    let runner = fs::read_to_string(repo_root.join(RUNNER_PATH)).expect("read runner script");
    let artifact: Value = serde_json::from_str(
        &fs::read_to_string(
            repo_root.join("artifacts/mean_field_capacity_planner_smoke_contract_v1.json"),
        )
        .expect("read mean-field capacity planner artifact"),
    )
    .expect("valid artifact json");

    assert_eq!(report["mode"].as_str(), Some("dry-run"));
    assert_eq!(report["status"].as_str(), Some("dry_run"));
    assert_eq!(report["validation_passed"].as_bool(), Some(true));
    assert!(
        report["command"]
            .as_str()
            .expect("command")
            .contains("rch exec --")
    );
    assert!(log.contains("MEAN_FIELD_CAPACITY_PLANNER command="));
    assert!(log.contains("rch exec --"));
    for marker in [
        "RCH_BIN=\"${RCH_BIN:-$HOME/.local/bin/rch}\"",
        "RCH_COMMAND=(\"${RCH_BIN}\" exec -- \"${PROOF_COMMAND[@]}\")",
        "falling back to local",
        "--dry-run",
    ] {
        assert!(runner.contains(marker), "runner missing marker: {marker}");
    }
    let validation_commands = artifact["validation_commands"]
        .as_array()
        .expect("validation_commands array");
    assert!(
        validation_commands
            .iter()
            .filter_map(Value::as_str)
            .any(|command| command.contains("--dry-run")),
        "artifact must include dry-run validation command"
    );
    assert!(
        validation_commands
            .iter()
            .filter_map(Value::as_str)
            .filter(|command| command.contains("cargo ") || command.starts_with("rustfmt "))
            .all(|command| command.contains("rch exec --")),
        "cargo/rustfmt validation commands must be rch-routed"
    );
}
