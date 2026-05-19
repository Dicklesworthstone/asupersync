//! Contract-backed proofs for controller-interference digital-twin signoff.

use asupersync::runtime::config::{
    CONTROLLER_INTERFERENCE_DIGITAL_TWIN_REPORT_SCHEMA_VERSION,
    ControllerInterferenceDigitalTwinReport, ControllerInterferenceDigitalTwinRequest,
    ControllerInterferenceFindingClass, ControllerInterferenceStateVector,
    ControllerInterferenceTwinBudget, ControllerInterferenceTwinVerdict, HostProfileId,
    SignedProfileBundleChildEvidenceHash, SignedProfileBundleControllerVersion,
    SignedProfileBundleShadowRunDecision,
};
use serde::Deserialize;
use serde_json::{Value, json};
use std::fs;
use std::path::Path;

const DEFAULT_SCENARIO_ID: &str = "AA-CONTROLLER-INTERFERENCE-DIGITAL-TWIN-64C-256G";

#[derive(Debug, Deserialize)]
struct ControllerInterferenceContract {
    contract_version: String,
    smoke_scenarios: Vec<ControllerInterferenceScenario>,
}

#[derive(Debug, Deserialize)]
struct ControllerInterferenceScenario {
    scenario_id: String,
    expected_verdict: String,
}

fn contract() -> ControllerInterferenceContract {
    serde_json::from_str(include_str!(
        "../artifacts/controller_interference_digital_twin_smoke_contract_v1.json"
    ))
    .expect("controller-interference digital-twin contract must parse")
}

fn runner_script() -> &'static str {
    include_str!("../scripts/run_controller_interference_digital_twin_smoke.sh")
}

fn controllers() -> [&'static str; 6] {
    [
        "admission",
        "batching",
        "brownout",
        "topology",
        "trace_retention",
        "capacity",
    ]
}

fn digest(seed: char) -> String {
    seed.to_string().repeat(64)
}

fn evidence_seed(controller: &str) -> char {
    match controller {
        "admission" => 'a',
        "batching" => 'b',
        "brownout" => 'c',
        "topology" => 'd',
        "trace_retention" => 'e',
        "capacity" => 'f',
        _ => '0',
    }
}

fn controller_version(controller: &str) -> SignedProfileBundleControllerVersion {
    SignedProfileBundleControllerVersion {
        controller: controller.to_string(),
        contract_version: format!("{controller}-v1"),
    }
}

fn evidence(controller: &str) -> SignedProfileBundleChildEvidenceHash {
    SignedProfileBundleChildEvidenceHash {
        controller: controller.to_string(),
        artifact_id: format!("artifacts/{controller}_smoke_contract_v1.json"),
        digest_sha256: digest(evidence_seed(controller)),
    }
}

fn state(
    step_index: u32,
    controller: &str,
    queue_pressure_basis_points: u16,
    tail_risk_basis_points: u16,
    memory_pressure_basis_points: u16,
) -> ControllerInterferenceStateVector {
    ControllerInterferenceStateVector {
        step_index,
        controller: controller.to_string(),
        contract_version: format!("{controller}-v1"),
        policy_hash: format!("sha256:{controller}-policy"),
        evidence_hash: digest(evidence_seed(controller)),
        confidence_percent: 94,
        evidence_age_hours: 4,
        queue_pressure_basis_points,
        tail_risk_basis_points,
        memory_pressure_basis_points,
        shed_noncritical_basis_points: 800,
        preserved_telemetry_basis_points: 9_400,
        target_agent_ceiling: 384,
        selected_profile: HostProfileId::LocalityFirst64C256G,
        no_win: false,
        fallback_active: false,
    }
}

fn stable_state_vectors() -> Vec<ControllerInterferenceStateVector> {
    vec![
        state(0, "admission", 4_200, 4_100, 4_300),
        state(1, "batching", 3_950, 4_000, 4_350),
        state(2, "brownout", 3_700, 3_900, 4_400),
        state(3, "topology", 3_500, 3_800, 4_450),
        state(4, "trace_retention", 3_350, 3_750, 4_500),
        state(5, "capacity", 3_200, 3_700, 4_550),
    ]
}

fn base_request() -> ControllerInterferenceDigitalTwinRequest {
    ControllerInterferenceDigitalTwinRequest {
        scenario_id: DEFAULT_SCENARIO_ID.to_string(),
        controller_versions: controllers()
            .iter()
            .map(|name| controller_version(name))
            .collect(),
        input_evidence_hashes: controllers().iter().map(|name| evidence(name)).collect(),
        state_vectors: stable_state_vectors(),
        bundle_manifest_digest_sha256: digest('1'),
        bundle_verification_accepted: true,
        bundle_verification_refusal_reasons: Vec::new(),
        signed_mode_required: true,
        shadow_run_decision: Some(SignedProfileBundleShadowRunDecision::Promote),
        shadow_run_hold_reasons: Vec::new(),
        budget: ControllerInterferenceTwinBudget::default(),
        replay_command: concat!(
            "rch exec -- env CARGO_TARGET_DIR=${TMPDIR:-/tmp}/",
            "rch_target_controller_interference_digital_twin_docs ",
            "cargo test -p asupersync --test controller_interference_digital_twin_contract"
        )
        .to_string(),
    }
}

fn has_class(
    report: &ControllerInterferenceDigitalTwinReport,
    class: ControllerInterferenceFindingClass,
) -> bool {
    report.findings.iter().any(|finding| finding.class == class)
}

fn report_json(report: &ControllerInterferenceDigitalTwinReport) -> Value {
    json!({
        "schema_version": report.schema_version,
        "scenario_id": report.scenario_id,
        "verdict": report.verdict.as_str(),
        "accepted": report.accepted,
        "no_win": report.no_win,
        "fallback_decision": report.fallback_decision,
        "bundle_manifest_digest_sha256": report.bundle_manifest_digest_sha256,
        "signed_mode_required": report.signed_mode_required,
        "state_vector_hash": report.state_vector_hash,
        "controller_versions": report.controller_versions.iter().map(|entry| {
            json!({
                "controller": entry.controller,
                "contract_version": entry.contract_version,
            })
        }).collect::<Vec<_>>(),
        "input_evidence_hashes": report.input_evidence_hashes.iter().map(|entry| {
            json!({
                "controller": entry.controller,
                "artifact_id": entry.artifact_id,
                "digest_sha256": entry.digest_sha256,
            })
        }).collect::<Vec<_>>(),
        "state_vectors": report.state_vectors.iter().map(|state| {
            json!({
                "step_index": state.step_index,
                "controller": state.controller,
                "contract_version": state.contract_version,
                "policy_hash": state.policy_hash,
                "evidence_hash": state.evidence_hash,
                "confidence_percent": state.confidence_percent,
                "evidence_age_hours": state.evidence_age_hours,
                "queue_pressure_basis_points": state.queue_pressure_basis_points,
                "tail_risk_basis_points": state.tail_risk_basis_points,
                "memory_pressure_basis_points": state.memory_pressure_basis_points,
                "shed_noncritical_basis_points": state.shed_noncritical_basis_points,
                "preserved_telemetry_basis_points": state.preserved_telemetry_basis_points,
                "target_agent_ceiling": state.target_agent_ceiling,
                "selected_profile": state.selected_profile.as_str(),
                "no_win": state.no_win,
                "fallback_active": state.fallback_active,
            })
        }).collect::<Vec<_>>(),
        "findings": report.findings.iter().map(|finding| {
            json!({
                "class": finding.class.as_str(),
                "severity": finding.severity.as_str(),
                "controllers": finding.controllers,
                "reason": finding.reason,
            })
        }).collect::<Vec<_>>(),
        "replay_command": report.replay_command,
    })
}

#[test]
fn controller_interference_twin_accepts_stable_controller_pack() {
    let report = base_request().evaluate();

    assert_eq!(
        report.schema_version,
        CONTROLLER_INTERFERENCE_DIGITAL_TWIN_REPORT_SCHEMA_VERSION
    );
    assert_eq!(report.verdict, ControllerInterferenceTwinVerdict::Pass);
    assert!(report.accepted);
    assert!(!report.no_win);
    assert!(report.findings.is_empty());
    assert_eq!(report.fallback_decision, "accept_combined_policy_bundle");
    assert_eq!(report.state_vector_hash.len(), 64);
}

#[test]
fn controller_interference_twin_fails_closed_for_stale_evidence_reuse() {
    let mut request = base_request();
    request.state_vectors[2].evidence_age_hours = 72;

    let report = request.evaluate();

    assert_eq!(
        report.verdict,
        ControllerInterferenceTwinVerdict::FailClosed
    );
    assert!(has_class(
        &report,
        ControllerInterferenceFindingClass::StaleEvidenceReuse
    ));
    assert_eq!(report.fallback_decision, "fail_closed_reject_bundle");
}

#[test]
fn controller_interference_twin_fails_closed_for_unclaimed_controller_state() {
    let mut request = base_request();
    request
        .input_evidence_hashes
        .push(SignedProfileBundleChildEvidenceHash {
            controller: "rogue".to_string(),
            artifact_id: "artifacts/rogue_smoke_contract_v1.json".to_string(),
            digest_sha256: digest('9'),
        });
    request
        .state_vectors
        .push(ControllerInterferenceStateVector {
            step_index: 6,
            controller: "rogue".to_string(),
            contract_version: "rogue-v1".to_string(),
            policy_hash: "sha256:rogue-policy".to_string(),
            evidence_hash: digest('9'),
            confidence_percent: 95,
            evidence_age_hours: 2,
            queue_pressure_basis_points: 4_000,
            tail_risk_basis_points: 4_000,
            memory_pressure_basis_points: 4_000,
            shed_noncritical_basis_points: 400,
            preserved_telemetry_basis_points: 9_600,
            target_agent_ceiling: 384,
            selected_profile: HostProfileId::LocalityFirst64C256G,
            no_win: false,
            fallback_active: false,
        });

    let report = request.evaluate();

    assert_eq!(
        report.verdict,
        ControllerInterferenceTwinVerdict::FailClosed
    );
    assert!(has_class(
        &report,
        ControllerInterferenceFindingClass::MissingEvidence
    ));
    assert!(
        report.findings.iter().any(|finding| {
            finding.controllers.len() == 1
                && finding.controllers[0] == "rogue"
                && finding
                    .reason
                    .contains("is not listed in controller_versions")
        }),
        "unclaimed controller findings missing from {:#?}",
        report.findings
    );
    assert_eq!(report.fallback_decision, "fail_closed_reject_bundle");
}

#[test]
fn controller_interference_twin_detects_oscillation() {
    let mut request = base_request();
    request.state_vectors = vec![
        state(0, "admission", 9_000, 4_000, 4_000),
        state(1, "batching", 3_000, 4_000, 4_000),
        state(2, "brownout", 8_700, 4_000, 4_000),
        state(3, "topology", 3_100, 4_000, 4_000),
        state(4, "trace_retention", 8_900, 4_000, 4_000),
        state(5, "capacity", 3_200, 4_000, 4_000),
    ];

    let report = request.evaluate();

    assert_eq!(report.verdict, ControllerInterferenceTwinVerdict::NoWin);
    assert!(has_class(
        &report,
        ControllerInterferenceFindingClass::Oscillation
    ));
    assert_eq!(report.fallback_decision, "hold_conservative_baseline");
}

#[test]
fn controller_interference_twin_detects_priority_inversion() {
    let mut request = base_request();
    request.state_vectors[4].shed_noncritical_basis_points = 5_500;
    request.state_vectors[4].preserved_telemetry_basis_points = 4_000;

    let report = request.evaluate();

    assert_eq!(report.verdict, ControllerInterferenceTwinVerdict::NoWin);
    assert!(has_class(
        &report,
        ControllerInterferenceFindingClass::PriorityInversion
    ));
}

#[test]
fn controller_interference_twin_detects_hidden_overload_transfer() {
    let mut request = base_request();
    request.state_vectors[0].queue_pressure_basis_points = 9_000;
    request.state_vectors[0].memory_pressure_basis_points = 3_000;
    request.state_vectors[0].tail_risk_basis_points = 3_000;
    request.state_vectors[1].queue_pressure_basis_points = 3_000;
    request.state_vectors[1].memory_pressure_basis_points = 8_900;
    request.state_vectors[1].tail_risk_basis_points = 8_600;

    let report = request.evaluate();

    assert_eq!(report.verdict, ControllerInterferenceTwinVerdict::NoWin);
    assert!(has_class(
        &report,
        ControllerInterferenceFindingClass::HiddenOverloadTransfer
    ));
}

#[test]
fn controller_interference_twin_detects_conflicting_no_win_decisions() {
    let mut request = base_request();
    request.state_vectors[2].no_win = true;
    request.state_vectors[2].fallback_active = true;
    request.state_vectors[2].target_agent_ceiling = 128;
    request.state_vectors[2].selected_profile = HostProfileId::ConservativeBaseline;
    request.state_vectors[5].target_agent_ceiling = 512;
    request.state_vectors[5].selected_profile = HostProfileId::LocalityFirst64C256G;

    let report = request.evaluate();

    assert_eq!(report.verdict, ControllerInterferenceTwinVerdict::NoWin);
    assert!(has_class(
        &report,
        ControllerInterferenceFindingClass::ConflictingNoWin
    ));
}

#[test]
fn controller_interference_twin_ordering_is_deterministic() {
    let request = base_request();
    let mut permuted = request.clone();
    permuted.controller_versions.reverse();
    permuted.input_evidence_hashes.reverse();
    permuted.state_vectors.reverse();

    let report = request.evaluate();
    let permuted_report = permuted.evaluate();

    assert_eq!(report.state_vector_hash, permuted_report.state_vector_hash);
    assert_eq!(
        report.controller_versions,
        permuted_report.controller_versions
    );
    assert_eq!(
        report.input_evidence_hashes,
        permuted_report.input_evidence_hashes
    );
    assert_eq!(report.findings, permuted_report.findings);
}

#[test]
fn controller_interference_digital_twin_smoke_emits_report() {
    let contract = contract();
    assert_eq!(
        contract.contract_version,
        "controller-interference-digital-twin-smoke-contract-v1"
    );
    let scenario = contract
        .smoke_scenarios
        .iter()
        .find(|scenario| scenario.scenario_id == DEFAULT_SCENARIO_ID)
        .expect("default controller-interference scenario");
    let report = base_request().evaluate();
    assert_eq!(report.verdict.as_str(), scenario.expected_verdict);
    assert!(report.accepted);
    assert!(!report.no_win);
    assert!(report.findings.is_empty());
    assert_eq!(report.controller_versions.len(), controllers().len());
    assert_eq!(report.input_evidence_hashes.len(), controllers().len());
    assert_eq!(report.state_vectors.len(), controllers().len());

    let report = report_json(&report);
    assert_eq!(
        report["schema_version"],
        json!(CONTROLLER_INTERFERENCE_DIGITAL_TWIN_REPORT_SCHEMA_VERSION)
    );
    assert_eq!(
        report["fallback_decision"],
        json!("accept_combined_policy_bundle")
    );
    let replay_command = report["replay_command"].as_str().expect("replay");
    assert!(
        replay_command.contains("rch exec -- env "),
        "replay command must use rch env routing: {replay_command}"
    );
    assert!(
        replay_command.contains("CARGO_TARGET_DIR="),
        "replay command must isolate Cargo output: {replay_command}"
    );
    assert!(
        !replay_command.contains("rch exec -- cargo"),
        "replay command must not use bare rch cargo routing: {replay_command}"
    );

    if let Ok(path) = std::env::var("ASUPERSYNC_CONTROLLER_INTERFERENCE_DIGITAL_TWIN_REPORT_PATH") {
        let compact_report = serde_json::to_string(&report).expect("report renders compactly");
        println!("ASUPERSYNC_CONTROLLER_INTERFERENCE_DIGITAL_TWIN_REPORT_JSON={compact_report}");
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
fn controller_interference_digital_twin_runner_rejects_full_rch_fallback_marker_set() {
    let runner = runner_script();
    let matcher_uses = runner
        .matches(r#"grep -Eiq "$RCH_LOCAL_FALLBACK_PATTERN""#)
        .count();
    assert!(
        matcher_uses >= 1,
        "runner must use the shared local fallback matcher at its rch gate"
    );

    for token in [
        "RCH_LOCAL_FALLBACK_PATTERN=",
        "[RCH\\] local",
        "falling back to local",
        "local fallback",
        "fallback to local",
        "executing locally",
    ] {
        assert!(
            runner.contains(token),
            "runner missing local fallback marker: {token}"
        );
    }
}
