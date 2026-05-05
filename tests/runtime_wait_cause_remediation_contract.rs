//! Runtime wait-cause remediation report contract invariants (asupersync-d87ytw.12).

#![allow(missing_docs)]

use asupersync::observability::{
    DeadlockCycle, DeadlockSeverity, DirectionalDeadlockReport,
    TAIL_LATENCY_TAXONOMY_CONTRACT_VERSION, WAIT_CAUSE_REMEDIATION_REPORT_SCHEMA_VERSION,
    WaitCauseCategory, WaitCauseObligationEvidence, WaitCauseRemediationEvidence,
    WaitCauseRemediationFinding, WaitCauseRemediationReport, WaitCauseRemediationVerdict,
    WaitCauseSeverity, WaitCauseTaskEvidence, WaitCauseTaskWaitKind,
    build_wait_cause_remediation_report,
};
use asupersync::types::{ObligationId, RegionId, TaskId};
use serde_json::{Value, json};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

const DOC_PATH: &str = "docs/runtime_wait_cause_remediation_contract.md";
const ARTIFACT_PATH: &str = "artifacts/runtime_wait_cause_remediation_v1.json";
const RUNNER_PATH: &str = "scripts/run_wait_cause_remediation_smoke.sh";

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn load_doc() -> String {
    std::fs::read_to_string(repo_root().join(DOC_PATH))
        .expect("failed to load wait-cause remediation doc")
}

fn load_artifact() -> Value {
    let raw = std::fs::read_to_string(repo_root().join(ARTIFACT_PATH))
        .expect("failed to load wait-cause remediation artifact");
    serde_json::from_str(&raw).expect("failed to parse wait-cause remediation artifact")
}

fn load_runner() -> String {
    std::fs::read_to_string(repo_root().join(RUNNER_PATH))
        .expect("failed to load wait-cause remediation runner")
}

fn task(index: u32) -> TaskId {
    TaskId::new_for_test(index, 0)
}

fn region(index: u32) -> RegionId {
    RegionId::new_for_test(index, 0)
}

fn obligation(index: u32) -> ObligationId {
    ObligationId::new_for_test(index, 0)
}

fn trapped_deadlock_report() -> DirectionalDeadlockReport {
    DirectionalDeadlockReport {
        severity: DeadlockSeverity::Critical,
        risk_score: 1.0,
        cycles: vec![DeadlockCycle {
            tasks: vec![task(1), task(2)],
            ingress_edges: 0,
            egress_edges: 0,
            trapped: true,
        }],
    }
}

fn base_evidence(report_id: &str, scenario_id: &str) -> WaitCauseRemediationEvidence {
    WaitCauseRemediationEvidence::new(
        report_id,
        scenario_id,
        format!("bash {RUNNER_PATH} --execute --scenario {scenario_id}"),
    )
    .with_evidence_refs(vec![
        ARTIFACT_PATH.to_string(),
        "artifacts/runtime_latency_budget_certificate_v1.json".to_string(),
        "artifacts/runtime_tail_latency_taxonomy_v1.json".to_string(),
    ])
}

fn actionable_report() -> WaitCauseRemediationReport {
    build_wait_cause_remediation_report(
        base_evidence("wait-cause-report-actionable", "WAIT-CAUSE-ACTIONABLE")
            .with_deadlock_report(trapped_deadlock_report())
            .with_task_waits(vec![
                WaitCauseTaskEvidence::new(
                    task(7),
                    Some(region(2)),
                    WaitCauseTaskWaitKind::AwaitingFuture,
                    "coordination receive producer",
                )
                .with_wait_age_ns(25_000),
            ])
            .with_obligation_leaks(vec![WaitCauseObligationEvidence::new(
                obligation(4),
                "SendPermit",
                Some(task(7)),
                region(2),
                35_000,
            )]),
    )
}

fn investigate_report() -> WaitCauseRemediationReport {
    build_wait_cause_remediation_report(
        base_evidence("wait-cause-report-investigate", "WAIT-CAUSE-INVESTIGATE").with_task_waits(
            vec![
                WaitCauseTaskEvidence::new(
                    task(3),
                    Some(region(1)),
                    WaitCauseTaskWaitKind::Unknown,
                    "opaque await point",
                )
                .with_wait_age_ns(12_000)
                .with_wake_pending(true),
            ],
        ),
    )
}

fn refused_report() -> WaitCauseRemediationReport {
    build_wait_cause_remediation_report(
        WaitCauseRemediationEvidence::new("wait-cause-report-refused", "WAIT-CAUSE-REFUSED", "")
            .with_tail_taxonomy_version("runtime-tail-latency-taxonomy-v0")
            .with_task_waits(vec![WaitCauseTaskEvidence::new(
                task(9),
                None,
                WaitCauseTaskWaitKind::AwaitingFuture,
                "producer",
            )]),
    )
}

fn finding_report_row(finding: &WaitCauseRemediationFinding) -> Value {
    json!({
        "finding_id": finding.finding_id,
        "rank": finding.rank,
        "category": finding.category.as_str(),
        "severity": finding.severity.as_str(),
        "confidence_basis_points": finding.confidence_basis_points,
        "reason_code": finding.reason_code,
        "summary": finding.summary,
        "blocked_resource": finding.blocked_resource,
        "owner_task_id": finding.owner_task_id,
        "owner_region_id": finding.owner_region_id,
        "evidence_refs": finding.evidence_refs,
        "safe_actions": finding.safe_actions,
        "forbidden_actions": finding.forbidden_actions,
        "replay_command": finding.replay_command,
    })
}

fn report_row(report: &WaitCauseRemediationReport) -> Value {
    json!({
        "report_id": report.report_id,
        "report_hash": report.report_hash,
        "scenario_id": report.scenario_id,
        "wait_cause_graph_hash": report.wait_cause_graph_hash,
        "tail_taxonomy_version": report.tail_taxonomy_version,
        "verdict": report.verdict.as_str(),
        "refusal_reason": report.refusal_reason,
        "finding_count": report.findings.len(),
        "safe_action_count": report.safe_actions.len(),
        "safe_actions": report.safe_actions,
        "forbidden_action_disclaimer": report.forbidden_action_disclaimer,
        "replay_command": report.replay_command,
        "evidence_refs": report.evidence_refs,
        "findings": report.findings.iter().map(finding_report_row).collect::<Vec<_>>(),
    })
}

#[test]
fn doc_exists_and_references_contract_surface() {
    assert!(Path::new(DOC_PATH).exists(), "doc must exist");
    let doc = load_doc();
    for required in [
        "asupersync-d87ytw.12",
        "Purpose",
        "Verifier Inputs",
        "Report Verdicts",
        "Finding Categories",
        "Fail-Closed Rules",
        "Safe Action Policy",
        "Smoke Runner",
        "Validation",
        ARTIFACT_PATH,
        RUNNER_PATH,
        "src/observability/diagnostics.rs",
    ] {
        assert!(doc.contains(required), "doc must mention {required}");
    }
}

#[test]
fn artifact_versions_match_code_and_taxonomy() {
    let artifact = load_artifact();
    assert_eq!(
        artifact["contract_version"].as_str(),
        Some(WAIT_CAUSE_REMEDIATION_REPORT_SCHEMA_VERSION)
    );
    assert_eq!(
        artifact["tail_taxonomy_contract_version"].as_str(),
        Some(TAIL_LATENCY_TAXONOMY_CONTRACT_VERSION)
    );
    assert_eq!(artifact["bead_id"].as_str(), Some("asupersync-d87ytw.12"));
    assert_eq!(artifact["runner_script"].as_str(), Some(RUNNER_PATH));
}

#[test]
fn artifact_covers_required_fields_categories_and_actions() {
    let artifact = load_artifact();
    let report_fields: BTreeSet<&str> = artifact["required_report_fields"]
        .as_array()
        .expect("required_report_fields must be array")
        .iter()
        .map(|field| field.as_str().expect("field must be string"))
        .collect();
    for required in [
        "report_id",
        "report_hash",
        "scenario_id",
        "wait_cause_graph_hash",
        "tail_taxonomy_version",
        "verdict",
        "refusal_reason",
        "finding_count",
        "safe_actions",
        "forbidden_action_disclaimer",
        "replay_command",
        "evidence_refs",
        "findings",
    ] {
        assert!(
            report_fields.contains(required),
            "report field missing {required}"
        );
    }

    let finding_fields: BTreeSet<&str> = artifact["required_finding_fields"]
        .as_array()
        .expect("required_finding_fields must be array")
        .iter()
        .map(|field| field.as_str().expect("field must be string"))
        .collect();
    for required in [
        "finding_id",
        "rank",
        "category",
        "severity",
        "confidence_basis_points",
        "reason_code",
        "blocked_resource",
        "owner_task_id",
        "owner_region_id",
        "safe_actions",
        "forbidden_actions",
        "replay_command",
    ] {
        assert!(
            finding_fields.contains(required),
            "finding field missing {required}"
        );
    }

    let categories: BTreeSet<&str> = artifact["finding_categories"]
        .as_array()
        .expect("finding_categories must be array")
        .iter()
        .map(|category| category.as_str().expect("category must be string"))
        .collect();
    for required in [
        WaitCauseCategory::DeadlockCycle.as_str(),
        WaitCauseCategory::Futurelock.as_str(),
        WaitCauseCategory::ObligationLeak.as_str(),
        WaitCauseCategory::UnknownWait.as_str(),
    ] {
        assert!(categories.contains(required), "missing category {required}");
    }
}

#[test]
fn runner_exists_and_routes_execute_through_rch() {
    assert!(Path::new(RUNNER_PATH).exists(), "runner must exist");
    let runner = load_runner();
    for required in [
        "--list",
        "--dry-run",
        "--execute",
        "rch exec -- env CARGO_INCREMENTAL=0",
        "ASUPERSYNC_WAIT_CAUSE_REMEDIATION_REPORT_PATH",
        "WAIT_CAUSE_REMEDIATION_REPORT_JSON_BEGIN",
        "wait_cause_graph_hash",
        "safe_actions",
        "forbidden_action_disclaimer",
    ] {
        assert!(runner.contains(required), "runner must contain {required}");
    }
}

#[test]
fn verifier_emits_actionable_investigate_and_refused_reports() {
    let actionable = actionable_report();
    assert_eq!(actionable.verdict, WaitCauseRemediationVerdict::Actionable);
    assert_eq!(actionable.findings.len(), 3);
    assert_eq!(
        actionable.findings[0].category,
        WaitCauseCategory::DeadlockCycle
    );
    assert_eq!(actionable.findings[0].severity, WaitCauseSeverity::Critical);

    let investigate = investigate_report();
    assert_eq!(
        investigate.verdict,
        WaitCauseRemediationVerdict::Investigate
    );
    assert_eq!(investigate.findings.len(), 1);
    assert_eq!(
        investigate.findings[0].category,
        WaitCauseCategory::UnknownWait
    );

    let refused = refused_report();
    assert_eq!(refused.verdict, WaitCauseRemediationVerdict::Refused);
    assert_eq!(refused.findings.len(), 0);
    assert_eq!(
        refused.refusal_reason.as_deref(),
        Some("missing_replay_command")
    );
}

#[test]
fn wait_cause_remediation_smoke_emits_report() {
    let report_path = std::env::var("ASUPERSYNC_WAIT_CAUSE_REMEDIATION_REPORT_PATH")
        .unwrap_or_else(|_| "target/wait-cause-remediation-smoke/report.json".to_string());
    let replay_command =
        format!("bash {RUNNER_PATH} --execute --output-root target/wait-cause-remediation-smoke");

    let actionable = actionable_report();
    let investigate = investigate_report();
    let refused = refused_report();

    let report = json!({
        "schema_version": "wait-cause-remediation-smoke-report-v1",
        "contract_version": WAIT_CAUSE_REMEDIATION_REPORT_SCHEMA_VERSION,
        "bead_id": "asupersync-d87ytw.12",
        "status": "passed",
        "artifact_path": report_path,
        "replay_command": replay_command,
        "rows": [
            report_row(&actionable),
            report_row(&investigate),
            report_row(&refused),
        ],
    });

    println!("WAIT_CAUSE_REMEDIATION_REPORT_JSON_BEGIN");
    println!(
        "{}",
        serde_json::to_string_pretty(&report).expect("serialize smoke report")
    );
    println!("WAIT_CAUSE_REMEDIATION_REPORT_JSON_END");

    let report_path = PathBuf::from(
        report["artifact_path"]
            .as_str()
            .expect("artifact path must be string"),
    );
    if let Some(parent) = report_path.parent() {
        std::fs::create_dir_all(parent).expect("create report parent");
    }
    std::fs::write(
        &report_path,
        serde_json::to_vec_pretty(&report).expect("serialize report file"),
    )
    .expect("write smoke report");
}
