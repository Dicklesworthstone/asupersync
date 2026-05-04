#![allow(missing_docs)]

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

const CONTRACT_PATH: &str = "artifacts/tokio_migration_operator_report_contract_v1.json";
const SHADOW_CONTRACT_PATH: &str = "artifacts/tokio_migration_shadow_workload_contract_v1.json";
const CANCEL_DELTA_CONTRACT_PATH: &str = "artifacts/tokio_migration_cancel_delta_contract_v1.json";

#[derive(Debug, Deserialize)]
struct OperatorReportContract {
    contract_version: String,
    schema_version: String,
    generated_for_bead: String,
    source_workload_contract: String,
    source_cancel_delta_contract: String,
    source_perf_report_contract: String,
    perf_evidence_policy: PerfEvidencePolicy,
    report_render_policy: ReportRenderPolicy,
    required_report_fields: Vec<String>,
    required_states: Vec<String>,
    validation_commands: Vec<String>,
    reports: Vec<OperatorReport>,
    golden_reports: Vec<GoldenReport>,
}

#[derive(Debug, Deserialize)]
struct PerfEvidencePolicy {
    p99_p999_deltas_required_when_present: bool,
    missing_perf_evidence: String,
    stale_perf_evidence: String,
    real_host_rollout_requires_real_host_template: bool,
}

#[derive(Debug, Deserialize)]
struct ReportRenderPolicy {
    state_order: Vec<String>,
    secret_redaction: String,
    proxy_claim_policy: String,
    graph_proof_policy: String,
}

#[derive(Debug, Deserialize, Serialize)]
struct OperatorReport {
    report_id: String,
    state: String,
    scenario_id: String,
    source_idiom: String,
    asupersync_rewrite: String,
    required_cx_capability_surface: String,
    invariant_gained: String,
    risk_remaining: String,
    artifact_paths: BTreeMap<String, String>,
    command_lines: BTreeMap<String, String>,
    performance_delta: PerformanceDelta,
    cancellation_loss_verdict: String,
    orphan_task_verdict: String,
    no_tokio_graph_proof: NoTokioGraphProof,
    operator_next_step: String,
    projection_hash: u64,
}

#[derive(Debug, Deserialize, Serialize)]
struct PerformanceDelta {
    status: String,
    scale_mode: String,
    p99_delta_micros: Option<i64>,
    p999_delta_micros: Option<i64>,
    throughput_delta_ops_per_sec: Option<i64>,
    sample_count: u64,
}

#[derive(Debug, Deserialize, Serialize)]
struct NoTokioGraphProof {
    command: String,
    expected_stdout: String,
    proof_ref: String,
}

#[derive(Debug, Deserialize)]
struct GoldenReport {
    artifact_id: String,
    report_id: String,
    state: String,
    projection_hash: u64,
}

fn repo_path(path: &str) -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(path)
}

fn load_contract() -> OperatorReportContract {
    let text = std::fs::read_to_string(repo_path(CONTRACT_PATH))
        .expect("operator report contract should exist");
    serde_json::from_str(&text).expect("operator report contract should parse")
}

fn load_shadow_scenario_ids() -> BTreeSet<String> {
    let text = std::fs::read_to_string(repo_path(SHADOW_CONTRACT_PATH))
        .expect("shadow workload contract should exist");
    let value: Value = serde_json::from_str(&text).expect("shadow workload contract should parse");
    value["scenarios"]
        .as_array()
        .expect("shadow scenarios should be an array")
        .iter()
        .map(|scenario| {
            scenario["scenario_id"]
                .as_str()
                .expect("shadow scenario id should be a string")
                .to_string()
        })
        .collect()
}

fn load_cancel_delta_by_scenario() -> BTreeMap<String, String> {
    let text = std::fs::read_to_string(repo_path(CANCEL_DELTA_CONTRACT_PATH))
        .expect("cancel delta contract should exist");
    let value: Value = serde_json::from_str(&text).expect("cancel delta contract should parse");
    value["deltas"]
        .as_array()
        .expect("cancel deltas should be an array")
        .iter()
        .map(|delta| {
            let scenario_id = delta["source_shadow_scenario_id"]
                .as_str()
                .expect("delta scenario id should be a string")
                .to_string();
            let invariant_name = delta["invariant_name"]
                .as_str()
                .expect("delta invariant should be a string")
                .to_string();
            (scenario_id, invariant_name)
        })
        .collect()
}

fn fnv1a64(bytes: &[u8]) -> u64 {
    let mut hash = 0xcbf29ce484222325_u64;
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}

fn performance_value(value: Option<i64>) -> String {
    value.map_or_else(|| "none".to_string(), |value| value.to_string())
}

fn projection_text(report: &OperatorReport) -> String {
    [
        report.report_id.as_str(),
        report.state.as_str(),
        report.scenario_id.as_str(),
        report.source_idiom.as_str(),
        report.asupersync_rewrite.as_str(),
        report.invariant_gained.as_str(),
        report.performance_delta.status.as_str(),
        performance_value(report.performance_delta.p99_delta_micros).as_str(),
        performance_value(report.performance_delta.p999_delta_micros).as_str(),
        report.cancellation_loss_verdict.as_str(),
        report.orphan_task_verdict.as_str(),
        report.operator_next_step.as_str(),
    ]
    .join("|")
}

fn projection_hash(report: &OperatorReport) -> u64 {
    fnv1a64(projection_text(report).as_bytes())
}

fn rendered_report(report: &OperatorReport) -> String {
    format!(
        "scenario_id={} source_idiom={} asupersync_rewrite={} required_cx_capability_surface={} invariant_gained={} risk_remaining={} p99_delta_micros={} p999_delta_micros={} cancellation_loss_verdict={} orphan_task_verdict={} no_tokio_graph_proof={} operator_next_step={}",
        report.scenario_id,
        report.source_idiom,
        report.asupersync_rewrite,
        report.required_cx_capability_surface,
        report.invariant_gained,
        report.risk_remaining,
        performance_value(report.performance_delta.p99_delta_micros),
        performance_value(report.performance_delta.p999_delta_micros),
        report.cancellation_loss_verdict,
        report.orphan_task_verdict,
        report.no_tokio_graph_proof.command,
        report.operator_next_step,
    )
}

#[test]
fn contract_declares_stable_version_and_source_artifacts() {
    let contract = load_contract();

    assert_eq!(
        contract.contract_version,
        "tokio-migration-operator-report-v1"
    );
    assert_eq!(
        contract.schema_version,
        "tokio-migration-operator-report-schema-v1"
    );
    assert_eq!(contract.generated_for_bead, "asupersync-migrep");
    assert_eq!(
        contract.source_workload_contract,
        "artifacts/tokio_migration_shadow_workload_contract_v1.json"
    );
    assert_eq!(
        contract.source_cancel_delta_contract,
        "artifacts/tokio_migration_cancel_delta_contract_v1.json"
    );
    assert_eq!(
        contract.source_perf_report_contract,
        "artifacts/tokio_migration_perf_report_contract_v1.json"
    );
    assert!(
        contract
            .perf_evidence_policy
            .p99_p999_deltas_required_when_present
    );
    assert_eq!(
        contract.perf_evidence_policy.missing_perf_evidence,
        "partial_hold"
    );
    assert_eq!(
        contract.perf_evidence_policy.stale_perf_evidence,
        "refuse_hold_conservative"
    );
    assert!(
        contract
            .perf_evidence_policy
            .real_host_rollout_requires_real_host_template
    );
}

#[test]
fn reports_cover_required_states_and_link_live_contracts() {
    let contract = load_contract();
    let required_states: BTreeSet<_> = contract.required_states.iter().cloned().collect();
    let actual_states: BTreeSet<_> = contract
        .reports
        .iter()
        .map(|report| report.state.clone())
        .collect();
    let shadow_scenarios = load_shadow_scenario_ids();
    let cancel_invariants = load_cancel_delta_by_scenario();

    assert_eq!(actual_states, required_states);
    assert_eq!(
        contract.report_render_policy.state_order, contract.required_states,
        "render order should stay explicit and deterministic"
    );
    assert!(
        contract
            .report_render_policy
            .secret_redaction
            .contains("sanitized")
    );
    assert!(
        contract
            .report_render_policy
            .proxy_claim_policy
            .contains("must_not_claim_real_host")
    );
    assert!(
        contract
            .report_render_policy
            .graph_proof_policy
            .contains("no_tokio")
    );

    for report in &contract.reports {
        assert!(
            shadow_scenarios.contains(&report.scenario_id),
            "report {} references missing shadow scenario {}",
            report.report_id,
            report.scenario_id
        );
        assert_eq!(
            cancel_invariants.get(&report.scenario_id),
            Some(&report.invariant_gained),
            "report {} must use the cancel-delta invariant for its scenario",
            report.report_id
        );
    }
}

#[test]
fn rendered_rows_include_operator_guidance_fields() {
    let contract = load_contract();
    let required_fields: BTreeSet<_> = contract.required_report_fields.iter().cloned().collect();

    for report in &contract.reports {
        let row = serde_json::to_value(report).expect("report row should serialize");
        for field in &required_fields {
            assert!(row.get(field).is_some(), "missing field {field}: {row}");
        }

        let rendered = rendered_report(report);
        for needle in [
            "scenario_id=",
            "source_idiom=",
            "asupersync_rewrite=",
            "required_cx_capability_surface=",
            "invariant_gained=",
            "risk_remaining=",
            "p99_delta_micros=",
            "p999_delta_micros=",
            "cancellation_loss_verdict=",
            "orphan_task_verdict=",
            "no_tokio_graph_proof=",
            "operator_next_step=",
        ] {
            assert!(rendered.contains(needle), "missing {needle}: {rendered}");
        }

        assert!(
            report.required_cx_capability_surface.contains("Cx"),
            "rewrite must name the required Cx capability surface: {report:?}"
        );
        assert!(
            !report.risk_remaining.is_empty() && !report.operator_next_step.is_empty(),
            "operator report must include risk and next step: {report:?}"
        );
    }
}

#[test]
fn performance_deltas_are_optional_only_for_partial_or_refused_reports() {
    let contract = load_contract();

    for report in &contract.reports {
        match report.performance_delta.status.as_str() {
            "present" | "present_no_win" => {
                assert!(
                    report.performance_delta.p99_delta_micros.is_some(),
                    "present performance evidence must include p99 delta: {report:?}"
                );
                assert!(
                    report.performance_delta.p999_delta_micros.is_some(),
                    "present performance evidence must include p999 delta: {report:?}"
                );
                assert!(
                    report
                        .performance_delta
                        .throughput_delta_ops_per_sec
                        .is_some(),
                    "present performance evidence must include throughput delta: {report:?}"
                );
                assert!(report.performance_delta.sample_count > 0);
                assert!(
                    report
                        .performance_delta
                        .scale_mode
                        .contains("small-deterministic-proxy"),
                    "small-mode proxy evidence must be labeled: {report:?}"
                );
            }
            "missing" | "stale" => {
                assert!(report.performance_delta.p99_delta_micros.is_none());
                assert!(report.performance_delta.p999_delta_micros.is_none());
                assert!(
                    report
                        .performance_delta
                        .throughput_delta_ops_per_sec
                        .is_none()
                );
                assert_eq!(report.performance_delta.sample_count, 0);
                assert!(
                    report.state == "partial_evidence" || report.state == "refuse_stale_evidence",
                    "missing/stale performance must not render as ready: {report:?}"
                );
            }
            other => panic!("unexpected performance status {other}"),
        }
    }
}

#[test]
fn no_tokio_graph_proof_and_command_links_are_pinned() {
    let contract = load_contract();
    let joined_commands = contract.validation_commands.join("\n");

    assert!(joined_commands.contains("rch exec -- rustfmt"));
    assert!(joined_commands.contains("rch exec -- env CARGO_INCREMENTAL=0"));
    assert!(joined_commands.contains("scripts/run_tokio_migration_shadow_workload_smoke.sh"));
    assert!(joined_commands.contains("rch exec -- cargo tree -e normal -p asupersync -i tokio"));

    for report in &contract.reports {
        let graph_command = report
            .command_lines
            .get("graph_proof")
            .expect("report should name graph proof command");
        assert_eq!(graph_command, &report.no_tokio_graph_proof.command);
        assert!(graph_command.starts_with("rch exec -- cargo tree"));
        assert_eq!(
            report.no_tokio_graph_proof.expected_stdout,
            "warning: nothing to print."
        );
        assert!(
            report
                .no_tokio_graph_proof
                .proof_ref
                .starts_with("asupersync-"),
            "graph proof should cite a bead id: {report:?}"
        );
        assert!(
            report
                .command_lines
                .get("test")
                .is_some_and(|command| command.contains("rch exec --")),
            "expensive test command must use rch: {report:?}"
        );
        assert!(
            report
                .artifact_paths
                .values()
                .any(|path| path.contains("operator_report_contract_v1")),
            "report should pin its operator snapshot path: {report:?}"
        );
    }
}

#[test]
fn golden_ready_and_hold_reports_have_stable_projection_hashes() {
    let contract = load_contract();
    let by_id: BTreeMap<_, _> = contract
        .reports
        .iter()
        .map(|report| (report.report_id.as_str(), report))
        .collect();

    for report in &contract.reports {
        assert_eq!(
            projection_hash(report),
            report.projection_hash,
            "report projection hash drifted for {}",
            report.report_id
        );
    }

    for golden in &contract.golden_reports {
        assert!(
            golden.artifact_id.starts_with("TM-OPERATOR-GOLDEN-"),
            "golden id should be stable: {}",
            golden.artifact_id
        );
        let report = by_id
            .get(golden.report_id.as_str())
            .unwrap_or_else(|| panic!("golden references missing report {}", golden.report_id));
        assert_eq!(golden.state, report.state);
        assert_eq!(golden.projection_hash, projection_hash(report));
    }

    let golden_states: BTreeSet<_> = contract
        .golden_reports
        .iter()
        .map(|golden| golden.state.as_str())
        .collect();
    assert!(golden_states.contains("ready_to_migrate"));
    assert!(golden_states.contains("hold_conservative"));
}
