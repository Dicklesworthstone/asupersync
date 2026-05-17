#![allow(missing_docs)]
//! Contract-backed proofs for controller provenance dashboards.

use asupersync::runtime::config::{
    CONTROLLER_PROVENANCE_DASHBOARD_SCHEMA_VERSION, ControllerProvenanceCommandClass,
    ControllerProvenanceDashboardReport, ControllerProvenanceDashboardRequest,
    ControllerProvenanceDashboardRow, ControllerProvenanceDashboardVerdict,
    ControllerProvenanceEvidenceKind,
};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::Path;

const DEFAULT_SCENARIO_ID: &str = "AA-CONTROLLER-PROVENANCE-DASHBOARD-64C-256G";

#[derive(Debug, Deserialize)]
struct DashboardContract {
    schema_version: String,
    required_owner_beads: Vec<String>,
    required_command_classes: Vec<String>,
    smoke_scenarios: Vec<DashboardScenario>,
}

#[derive(Debug, Deserialize)]
struct DashboardScenario {
    scenario_id: String,
    expected_verdict: String,
    expected_row_count: usize,
    expected_unsupported_rows: Vec<String>,
}

fn contract() -> DashboardContract {
    serde_json::from_str(include_str!(
        "../artifacts/controller_provenance_dashboard_contract_v1.json"
    ))
    .expect("controller provenance dashboard contract must parse")
}

fn artifact_digest(path: &str) -> String {
    let bytes = fs::read(path).unwrap_or_else(|err| panic!("artifact {path} must load: {err}"));
    let digest = Sha256::digest(bytes);
    digest
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>()
}

fn digest(seed: char) -> String {
    seed.to_string().repeat(64)
}

fn row(
    decision_id: &str,
    owner_bead: &str,
    controller: &str,
    evidence_kind: ControllerProvenanceEvidenceKind,
    artifact_path: &str,
    command_class: ControllerProvenanceCommandClass,
    replay_command: &str,
) -> ControllerProvenanceDashboardRow {
    let artifact_sha256 = artifact_digest(artifact_path);
    ControllerProvenanceDashboardRow {
        decision_id: decision_id.to_string(),
        owner_bead: owner_bead.to_string(),
        controller: controller.to_string(),
        contract_version: format!("{controller}-v1"),
        evidence_kind,
        source_artifact_path: artifact_path.to_string(),
        expected_artifact_sha256: artifact_sha256.clone(),
        observed_artifact_sha256: artifact_sha256,
        certificate_artifact_ids: Vec::new(),
        bundle_signature_digest_sha256: None,
        command_class,
        replay_command: replay_command.to_string(),
        fallback_reason: None,
        no_win: false,
        unsupported: false,
        proxy_only: false,
    }
}

fn base_rows() -> Vec<ControllerProvenanceDashboardRow> {
    let mut rows = vec![
        row(
            "redacted_coordination_ingestion",
            "asupersync-d87ytw.1",
            "coordination_ingestion",
            ControllerProvenanceEvidenceKind::SourceEvidence,
            "artifacts/agent_swarm_coordination_redaction_contract_v1.json",
            ControllerProvenanceCommandClass::SmokeRunner,
            "bash scripts/run_coordination_workload_bridge_signoff.sh --dry-run",
        ),
        row(
            "latency_budget_certificate",
            "asupersync-d87ytw.2",
            "latency_budget",
            ControllerProvenanceEvidenceKind::LatencyCertificate,
            "artifacts/runtime_latency_budget_certificate_v1.json",
            ControllerProvenanceCommandClass::RchCargoTest,
            "timeout 900 rch exec -- env CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_controller_provenance_latency cargo test -p asupersync --test runtime_capacity_hints_contract --features test-internals",
        ),
        row(
            "mean_field_capacity_plan",
            "asupersync-d87ytw.3",
            "mean_field_capacity",
            ControllerProvenanceEvidenceKind::CapacityCertificate,
            "artifacts/mean_field_capacity_planner_smoke_contract_v1.json",
            ControllerProvenanceCommandClass::SmokeRunner,
            "bash scripts/run_mean_field_capacity_planner_smoke.sh --dry-run",
        ),
        row(
            "signed_controller_bundle",
            "asupersync-d87ytw.4",
            "signed_profile_bundle",
            ControllerProvenanceEvidenceKind::BundleSignature,
            "artifacts/signed_profile_bundle_smoke_contract_v1.json",
            ControllerProvenanceCommandClass::SmokeRunner,
            "bash scripts/run_signed_profile_bundle_smoke.sh --dry-run",
        ),
        row(
            "tail_causal_attribution",
            "asupersync-d87ytw.5",
            "tail_attribution",
            ControllerProvenanceEvidenceKind::SourceEvidence,
            "artifacts/runtime_tail_latency_taxonomy_v1.json",
            ControllerProvenanceCommandClass::ReplayCommand,
            "asupersync lab replay --artifact artifacts/runtime_tail_latency_taxonomy_v1.json",
        ),
        row(
            "controller_interference_twin",
            "asupersync-d87ytw.6",
            "controller_interference",
            ControllerProvenanceEvidenceKind::InterferenceReport,
            "artifacts/controller_interference_digital_twin_smoke_contract_v1.json",
            ControllerProvenanceCommandClass::SmokeRunner,
            "bash scripts/run_controller_interference_digital_twin_smoke.sh --dry-run",
        ),
        row(
            "shadow_promote_rollback_receipt",
            "asupersync-d87ytw.7",
            "shadow_promotion",
            ControllerProvenanceEvidenceKind::ShadowReceipt,
            "artifacts/shadow_promote_rollback_receipts_smoke_contract_v1.json",
            ControllerProvenanceCommandClass::SmokeRunner,
            "bash scripts/run_shadow_promote_rollback_receipts_smoke.sh --dry-run",
        ),
        row(
            "unified_admission_brownout_contract",
            "asupersync-d87ytw.8",
            "admission_brownout",
            ControllerProvenanceEvidenceKind::UnsupportedNoWin,
            "artifacts/unified_admission_brownout_smoke_contract_v1.json",
            ControllerProvenanceCommandClass::SmokeRunner,
            "bash scripts/run_controller_artifact_verifier_smoke.sh --dry-run",
        ),
        row(
            "trace_storage_profile",
            "asupersync-d87ytw.9",
            "trace_storage",
            ControllerProvenanceEvidenceKind::SourceEvidence,
            "artifacts/trace_storage_profile_smoke_contract_v1.json",
            ControllerProvenanceCommandClass::SmokeRunner,
            "bash scripts/run_trace_storage_profile_smoke.sh --dry-run",
        ),
        row(
            "numa_capacity_certificate_merger",
            "asupersync-d87ytw.10",
            "numa_capacity",
            ControllerProvenanceEvidenceKind::CapacityCertificate,
            "artifacts/numa_arena_locality_smoke_contract_v1.json",
            ControllerProvenanceCommandClass::SmokeRunner,
            "bash scripts/run_controller_artifact_verifier_smoke.sh --dry-run",
        ),
        row(
            "rch_proof_queue_feedback",
            "asupersync-d87ytw.11",
            "proof_queue",
            ControllerProvenanceEvidenceKind::SourceEvidence,
            "artifacts/compile_frontier_movement_proof_v1.json",
            ControllerProvenanceCommandClass::SmokeRunner,
            "bash scripts/run_controller_artifact_verifier_smoke.sh --dry-run",
        ),
        row(
            "wait_cause_remediation_report",
            "asupersync-d87ytw.12",
            "wait_cause",
            ControllerProvenanceEvidenceKind::SourceEvidence,
            "artifacts/runtime_wait_cause_remediation_v1.json",
            ControllerProvenanceCommandClass::ReplayCommand,
            "asupersync lab replay --artifact artifacts/runtime_wait_cause_remediation_v1.json",
        ),
        row(
            "session_typed_obligation_proofs",
            "asupersync-d87ytw.13",
            "session_obligation",
            ControllerProvenanceEvidenceKind::SourceEvidence,
            "artifacts/formal_proof_posture_contract_v1.json",
            ControllerProvenanceCommandClass::RchCargoTest,
            "timeout 900 rch exec -- env CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_controller_provenance_session cargo test -p asupersync --test session_type_obligations --features test-internals",
        ),
    ];
    for row in &mut rows {
        row.certificate_artifact_ids = vec![
            "artifacts/capacity_envelope_planner_smoke_contract_v1.json".to_string(),
            "artifacts/runtime_latency_budget_certificate_v1.json".to_string(),
        ];
    }
    rows[3].bundle_signature_digest_sha256 = Some(digest('b'));
    rows[7].no_win = true;
    rows[7].fallback_reason = Some(
        "admission and brownout policy remains explicit no-win until operator signoff".to_string(),
    );
    rows
}

fn base_request() -> ControllerProvenanceDashboardRequest {
    ControllerProvenanceDashboardRequest {
        scenario_id: DEFAULT_SCENARIO_ID.to_string(),
        required_owner_beads: contract().required_owner_beads,
        rows: base_rows(),
        replay_command: "bash scripts/run_controller_provenance_dashboard_smoke.sh --dry-run"
            .to_string(),
    }
}

fn row_json(row: &ControllerProvenanceDashboardRow) -> Value {
    json!({
        "decision_id": row.decision_id.clone(),
        "owner_bead": row.owner_bead.clone(),
        "controller": row.controller.clone(),
        "contract_version": row.contract_version.clone(),
        "evidence_kind": row.evidence_kind.as_str(),
        "source_artifact_path": row.source_artifact_path.clone(),
        "expected_artifact_sha256": row.expected_artifact_sha256.clone(),
        "observed_artifact_sha256": row.observed_artifact_sha256.clone(),
        "certificate_artifact_ids": row.certificate_artifact_ids.clone(),
        "bundle_signature_digest_sha256": row.bundle_signature_digest_sha256.clone(),
        "command_class": row.command_class.as_str(),
        "replay_command": row.replay_command.clone(),
        "fallback_reason": row.fallback_reason.clone(),
        "no_win": row.no_win,
        "unsupported": row.unsupported,
        "proxy_only": row.proxy_only,
    })
}

fn report_json(report: &ControllerProvenanceDashboardReport) -> Value {
    json!({
        "schema_version": report.schema_version.clone(),
        "scenario_id": report.scenario_id.clone(),
        "verdict": report.verdict.as_str(),
        "accepted": report.accepted,
        "no_win": report.no_win,
        "fallback_decision": report.fallback_decision.clone(),
        "required_owner_beads": report.required_owner_beads.clone(),
        "owner_beads": report.owner_beads.clone(),
        "row_count": report.row_count,
        "rows": report.rows.iter().map(row_json).collect::<Vec<_>>(),
        "unsupported_rows": report.unsupported_rows.clone(),
        "failure_reasons": report.failure_reasons.clone(),
        "first_failure": report.first_failure.clone(),
        "dashboard_digest_sha256": report.dashboard_digest_sha256.clone(),
        "markdown": report.markdown.clone(),
        "replay_command": report.replay_command.clone(),
    })
}

#[test]
fn controller_provenance_dashboard_accepts_complete_child_provenance() {
    let contract = contract();
    let scenario = &contract.smoke_scenarios[0];
    let report = base_request().evaluate();

    assert_eq!(
        contract.schema_version,
        CONTROLLER_PROVENANCE_DASHBOARD_SCHEMA_VERSION
    );
    assert_eq!(scenario.scenario_id, report.scenario_id);
    assert_eq!(scenario.expected_verdict, report.verdict.as_str());
    assert_eq!(scenario.expected_row_count, report.row_count);
    assert_eq!(scenario.expected_unsupported_rows, report.unsupported_rows);
    assert_eq!(
        contract.required_command_classes,
        vec!["rch_cargo_test", "smoke_runner", "replay_command"]
    );
    assert!(!report.accepted, "no-win rows must hold final signoff");
    assert!(
        report.no_win,
        "explicit no-win row should surface in report"
    );
    assert!(
        report.failure_reasons.is_empty(),
        "{:?}",
        report.failure_reasons
    );
    assert_eq!(
        report.schema_version,
        CONTROLLER_PROVENANCE_DASHBOARD_SCHEMA_VERSION
    );
    assert_eq!(report.dashboard_digest_sha256.len(), 64);
}

#[test]
fn controller_provenance_dashboard_rch_rows_use_target_dirs() {
    let rows = base_rows()
        .into_iter()
        .filter(|row| row.command_class == ControllerProvenanceCommandClass::RchCargoTest)
        .collect::<Vec<_>>();

    assert_eq!(rows.len(), 2, "expected exactly two RCH cargo replay rows");
    for row in rows {
        assert!(
            row.replay_command
                .contains("rch exec -- env CARGO_TARGET_DIR=${TMPDIR:-/tmp}/"),
            "RCH cargo row must set a target dir: {}",
            row.replay_command
        );
        assert!(
            !row.replay_command.contains("rch exec -- cargo "),
            "RCH cargo row must not use stale bare routing: {}",
            row.replay_command
        );
    }
}

#[test]
fn controller_provenance_dashboard_runner_rejects_full_rch_fallback_marker_set() {
    let script_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("scripts/run_controller_provenance_dashboard_smoke.sh");
    let script = fs::read_to_string(&script_path).expect("runner script must load");

    for token in [
        "RCH_LOCAL_FALLBACK_PATTERN=",
        r#"grep -Eiq "$RCH_LOCAL_FALLBACK_PATTERN""#,
        "[RCH\\] local",
        "falling back to local",
        "local fallback",
        "fallback to local",
        "executing locally",
        "rch local fallback detected; refusing local cargo execution",
    ] {
        assert!(script.contains(token), "runner missing token: {token}");
    }
}

#[test]
fn controller_provenance_dashboard_rejects_missing_child_rows() {
    let mut request = base_request();
    request
        .rows
        .retain(|row| row.owner_bead != "asupersync-d87ytw.7");

    let report = request.evaluate();

    assert_eq!(
        report.verdict,
        ControllerProvenanceDashboardVerdict::FailClosed
    );
    assert!(report.first_failure.as_deref().is_some_and(|reason| {
        reason.contains("required owner bead asupersync-d87ytw.7 has no provenance row")
    }));
}

#[test]
fn controller_provenance_dashboard_rejects_stale_checksums() {
    let mut request = base_request();
    request.rows[0].observed_artifact_sha256 = digest('f');

    let report = request.evaluate();

    assert_eq!(
        report.verdict,
        ControllerProvenanceDashboardVerdict::FailClosed
    );
    assert!(
        report
            .failure_reasons
            .iter()
            .any(|reason| reason.contains("artifact checksum mismatch")),
        "{:?}",
        report.failure_reasons
    );
}

#[test]
fn controller_provenance_dashboard_rejects_proxy_only_evidence() {
    let mut request = base_request();
    request.rows[2].proxy_only = true;

    let report = request.evaluate();

    assert_eq!(
        report.verdict,
        ControllerProvenanceDashboardVerdict::FailClosed
    );
    assert!(
        report
            .failure_reasons
            .iter()
            .any(|reason| reason.contains("proxy-only")),
        "{:?}",
        report.failure_reasons
    );
}

#[test]
fn controller_provenance_dashboard_requires_explicit_no_win_fallback() {
    let mut request = base_request();
    request.rows[7].fallback_reason = None;

    let report = request.evaluate();

    assert_eq!(
        report.verdict,
        ControllerProvenanceDashboardVerdict::FailClosed
    );
    assert!(
        report
            .failure_reasons
            .iter()
            .any(|reason| reason.contains("fallback_reason")),
        "{:?}",
        report.failure_reasons
    );
}

#[test]
fn controller_provenance_dashboard_row_ordering_is_deterministic() {
    let mut reversed = base_request();
    reversed.rows.reverse();

    let forward_report = base_request().evaluate();
    let reversed_report = reversed.evaluate();

    assert_eq!(
        forward_report.dashboard_digest_sha256,
        reversed_report.dashboard_digest_sha256
    );
    assert_eq!(
        forward_report
            .rows
            .iter()
            .map(|row| row.decision_id.as_str())
            .collect::<Vec<_>>(),
        reversed_report
            .rows
            .iter()
            .map(|row| row.decision_id.as_str())
            .collect::<Vec<_>>()
    );
}

#[test]
fn controller_provenance_dashboard_markdown_matches_json_rows() {
    let report = base_request().evaluate();
    let json_report = report_json(&report);
    let markdown = json_report["markdown"].as_str().expect("markdown string");

    for row in json_report["rows"].as_array().expect("rows array") {
        let decision_id = row["decision_id"].as_str().expect("decision id");
        let owner_bead = row["owner_bead"].as_str().expect("owner bead");
        assert!(markdown.contains(decision_id), "missing {decision_id}");
        assert!(markdown.contains(owner_bead), "missing {owner_bead}");
    }
}

#[test]
fn controller_provenance_dashboard_smoke_emits_report() {
    let report = base_request().evaluate();
    let json_report = report_json(&report);
    let report_path = std::env::var("ASUPERSYNC_CONTROLLER_PROVENANCE_DASHBOARD_REPORT_PATH").ok();
    let markdown_path =
        std::env::var("ASUPERSYNC_CONTROLLER_PROVENANCE_DASHBOARD_MARKDOWN_PATH").ok();

    if let Some(path) = report_path.as_deref() {
        let path = Path::new(path);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).expect("report parent dir");
        }
        fs::write(
            path,
            serde_json::to_string_pretty(&json_report).expect("report JSON"),
        )
        .expect("write controller provenance dashboard report");
    }
    if let Some(path) = markdown_path.as_deref() {
        let path = Path::new(path);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).expect("markdown parent dir");
        }
        fs::write(path, &report.markdown).expect("write controller provenance dashboard markdown");
    }

    println!(
        "ASUPERSYNC_CONTROLLER_PROVENANCE_DASHBOARD_JSON={}",
        serde_json::to_string(&json_report).expect("compact report JSON")
    );

    assert_eq!(report.verdict, ControllerProvenanceDashboardVerdict::NoWin);
    assert_eq!(report.row_count, 13);
    assert!(
        report.failure_reasons.is_empty(),
        "{:?}",
        report.failure_reasons
    );
}
