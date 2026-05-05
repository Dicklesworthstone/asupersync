#![allow(missing_docs)]
//! Final control-loop signoff audit contract tests.

use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::env;
use std::fs;
use std::path::Path;

const SCHEMA_VERSION: &str = "final-control-loop-signoff-v1";
const DEFAULT_SCENARIO_ID: &str = "AA-FINAL-CONTROL-LOOP-SIGNOFF-64C-256G";
const DIRTY_PATH_ENV: &str = "ASUPERSYNC_FINAL_CONTROL_LOOP_SIGNOFF_DIRTY_PATHS";
const DIRTY_FALLBACK_REASON: &str = "Peer-owned dirty work remains visible in the shared worktree, so final parent epic closure must stay no-win until that owner commits or releases it.";

#[derive(Debug, Deserialize)]
struct SignoffContract {
    schema_version: String,
    parent_bead: String,
    parent_expected_status: String,
    required_child_beads: Vec<String>,
    required_certificate_artifacts: Vec<String>,
    smoke_scenarios: Vec<SignoffScenario>,
    checklist_rows: Vec<ChecklistRow>,
    dirty_blockers: Vec<DirtyBlocker>,
}

#[derive(Debug, Deserialize)]
struct SignoffScenario {
    scenario_id: String,
    expected_verdict: String,
    expected_child_rows: usize,
    expected_dirty_blockers: Option<usize>,
    expected_no_win_rows: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct ChecklistRow {
    requirement_id: String,
    owner_bead: String,
    artifact_path: String,
    command_class: String,
    proof_command: String,
    child_status: String,
    fallback_status: String,
    proxy_only: bool,
}

#[derive(Debug, Clone, Deserialize)]
struct DirtyBlocker {
    blocker_id: String,
    path: String,
    blocker_type: String,
    retention_policy: String,
    fallback_reason: String,
}

#[derive(Debug, Clone)]
struct RowReport {
    row: ChecklistRow,
    expected_artifact_sha256: String,
    observed_artifact_sha256: String,
}

#[derive(Debug)]
struct SignoffReport {
    schema_version: String,
    scenario_id: String,
    verdict: String,
    accepted: bool,
    no_win: bool,
    parent_bead: String,
    parent_expected_status: String,
    child_row_count: usize,
    required_child_beads: Vec<String>,
    no_win_rows: Vec<String>,
    dirty_blockers: Vec<DirtyBlocker>,
    certificate_artifacts: Vec<String>,
    failure_reasons: Vec<String>,
    first_failure: Option<String>,
    rows: Vec<RowReport>,
    signoff_digest_sha256: String,
    markdown: String,
}

fn contract() -> SignoffContract {
    serde_json::from_str(include_str!(
        "../artifacts/final_control_loop_signoff_contract_v1.json"
    ))
    .expect("final control-loop signoff contract must parse")
}

fn dirty_blockers(contract: &SignoffContract) -> Vec<DirtyBlocker> {
    let Ok(raw_paths) = env::var(DIRTY_PATH_ENV) else {
        return contract.dirty_blockers.clone();
    };
    let mut paths = raw_paths
        .split(',')
        .map(str::trim)
        .filter(|path| !path.is_empty())
        .map(ToOwned::to_owned)
        .collect::<Vec<_>>();
    paths.sort();
    paths.dedup();

    paths
        .into_iter()
        .map(|path| DirtyBlocker {
            blocker_id: format!("peer_dirty_{}", blocker_path_id(&path)),
            path,
            blocker_type: "peer_dirty_worktree".to_string(),
            retention_policy: "block_parent_epic_close".to_string(),
            fallback_reason: DIRTY_FALLBACK_REASON.to_string(),
        })
        .collect()
}

fn blocker_path_id(path: &str) -> String {
    path.chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() {
                ch.to_ascii_lowercase()
            } else {
                '_'
            }
        })
        .collect::<String>()
        .trim_matches('_')
        .to_string()
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

fn row_reports(contract: &SignoffContract) -> Vec<RowReport> {
    contract
        .checklist_rows
        .iter()
        .cloned()
        .map(|row| {
            let artifact_sha256 = artifact_digest(&row.artifact_path);
            RowReport {
                row,
                expected_artifact_sha256: artifact_sha256.clone(),
                observed_artifact_sha256: artifact_sha256,
            }
        })
        .collect()
}

fn evaluate(
    contract: &SignoffContract,
    scenario: &SignoffScenario,
    mut rows: Vec<RowReport>,
    dirty_blockers: Vec<DirtyBlocker>,
) -> SignoffReport {
    rows.sort_by(|left, right| {
        left.row
            .requirement_id
            .cmp(&right.row.requirement_id)
            .then_with(|| left.row.owner_bead.cmp(&right.row.owner_bead))
    });

    let mut failure_reasons = Vec::new();
    if contract.schema_version != SCHEMA_VERSION {
        failure_reasons.push("schema_version mismatch".to_string());
    }
    if contract.parent_expected_status != "open" {
        failure_reasons.push("parent epic must remain open until signoff is accepted".to_string());
    }
    for child in &contract.required_child_beads {
        if !rows.iter().any(|row| row.row.owner_bead == *child) {
            failure_reasons.push(format!("required child bead {child} has no checklist row"));
        }
    }
    for certificate in &contract.required_certificate_artifacts {
        if !Path::new(certificate).exists() {
            failure_reasons.push(format!(
                "required certificate artifact {certificate} is missing"
            ));
        }
    }
    for row in &rows {
        validate_row(row, &mut failure_reasons);
    }
    for blocker in &dirty_blockers {
        validate_dirty_blocker(blocker, &mut failure_reasons);
    }
    failure_reasons.sort();
    failure_reasons.dedup();

    let no_win_rows = rows
        .iter()
        .filter(|row| row.row.fallback_status == "no_win")
        .map(|row| row.row.requirement_id.clone())
        .collect::<Vec<_>>();
    let verdict = if failure_reasons.is_empty() {
        if no_win_rows.is_empty() && dirty_blockers.is_empty() {
            "pass"
        } else {
            "no_win"
        }
    } else {
        "fail_closed"
    }
    .to_string();
    let accepted = verdict == "pass";
    let markdown = render_markdown(
        &scenario.scenario_id,
        &verdict,
        &rows,
        &dirty_blockers,
        &failure_reasons,
    );
    let signoff_digest_sha256 = signoff_digest(
        &scenario.scenario_id,
        &verdict,
        &rows,
        &dirty_blockers,
        &failure_reasons,
    );

    SignoffReport {
        schema_version: contract.schema_version.clone(),
        scenario_id: scenario.scenario_id.clone(),
        verdict,
        accepted,
        no_win: !accepted && failure_reasons.is_empty(),
        parent_bead: contract.parent_bead.clone(),
        parent_expected_status: contract.parent_expected_status.clone(),
        child_row_count: rows.len(),
        required_child_beads: contract.required_child_beads.clone(),
        no_win_rows,
        dirty_blockers,
        certificate_artifacts: contract.required_certificate_artifacts.clone(),
        first_failure: failure_reasons.first().cloned(),
        failure_reasons,
        rows,
        signoff_digest_sha256,
        markdown,
    }
}

fn validate_row(row: &RowReport, failure_reasons: &mut Vec<String>) {
    if row.row.requirement_id.trim().is_empty() {
        failure_reasons.push("requirement_id must not be empty".to_string());
    }
    if row.row.owner_bead.trim().is_empty() {
        failure_reasons.push(format!(
            "{} owner_bead must not be empty",
            row.row.requirement_id
        ));
    }
    if !Path::new(&row.row.artifact_path).exists() {
        failure_reasons.push(format!(
            "{} artifact {} is missing",
            row.row.requirement_id, row.row.artifact_path
        ));
    }
    if row.expected_artifact_sha256 != row.observed_artifact_sha256 {
        failure_reasons.push(format!(
            "{} artifact checksum mismatch",
            row.row.requirement_id
        ));
    }
    if row.row.child_status != "closed" {
        failure_reasons.push(format!(
            "{} child bead status was {} not closed",
            row.row.requirement_id, row.row.child_status
        ));
    }
    if row.row.proxy_only {
        failure_reasons.push(format!("{} is proxy-only evidence", row.row.requirement_id));
    }
    if let Some(reason) = validate_command(&row.row.command_class, &row.row.proof_command) {
        failure_reasons.push(format!("{} {reason}", row.row.requirement_id));
    }
    if !matches!(
        row.row.fallback_status.as_str(),
        "pass" | "no_win" | "fail_closed"
    ) {
        failure_reasons.push(format!(
            "{} fallback_status must be pass, no_win, or fail_closed",
            row.row.requirement_id
        ));
    }
}

fn validate_command(command_class: &str, proof_command: &str) -> Option<String> {
    match command_class {
        "rch_cargo_test" => {
            if proof_command.contains("rch exec") && proof_command.contains("cargo test") {
                None
            } else {
                Some("rch_cargo_test command must contain `rch exec` and `cargo test`".to_string())
            }
        }
        "smoke_runner" => {
            if proof_command.starts_with("bash scripts/run_") && proof_command.contains(".sh") {
                None
            } else {
                Some("smoke_runner command must start with `bash scripts/run_`".to_string())
            }
        }
        "replay_command" => {
            if proof_command.contains("replay") {
                None
            } else {
                Some("replay_command must contain `replay`".to_string())
            }
        }
        other => Some(format!("unknown command_class {other}")),
    }
}

fn validate_dirty_blocker(blocker: &DirtyBlocker, failure_reasons: &mut Vec<String>) {
    if blocker.blocker_id.trim().is_empty() {
        failure_reasons.push("dirty blocker id must not be empty".to_string());
    }
    if blocker.path.trim().is_empty() {
        failure_reasons.push(format!("{} path must not be empty", blocker.blocker_id));
    }
    if blocker.blocker_type.trim().is_empty() {
        failure_reasons.push(format!(
            "{} blocker_type must not be empty",
            blocker.blocker_id
        ));
    }
    if blocker.retention_policy != "block_parent_epic_close" {
        failure_reasons.push(format!(
            "{} dirty blocker must block parent epic close",
            blocker.blocker_id
        ));
    }
    if blocker.fallback_reason.trim().is_empty() {
        failure_reasons.push(format!(
            "{} fallback_reason must not be empty",
            blocker.blocker_id
        ));
    }
}

fn signoff_digest(
    scenario_id: &str,
    verdict: &str,
    rows: &[RowReport],
    dirty_blockers: &[DirtyBlocker],
    failure_reasons: &[String],
) -> String {
    let mut hasher = Sha256::new();
    for part in [
        SCHEMA_VERSION.to_string(),
        scenario_id.to_string(),
        verdict.to_string(),
        rows.iter()
            .map(|row| {
                format!(
                    "{}|{}|{}|{}|{}|{}",
                    row.row.requirement_id,
                    row.row.owner_bead,
                    row.row.artifact_path,
                    row.observed_artifact_sha256,
                    row.row.command_class,
                    row.row.fallback_status
                )
            })
            .collect::<Vec<_>>()
            .join(";"),
        dirty_blockers
            .iter()
            .map(|blocker| {
                format!(
                    "{}|{}|{}|{}",
                    blocker.blocker_id,
                    blocker.path,
                    blocker.blocker_type,
                    blocker.retention_policy
                )
            })
            .collect::<Vec<_>>()
            .join(";"),
        failure_reasons.join("|"),
    ] {
        hasher.update(part.as_bytes());
        hasher.update([0xff]);
    }
    hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>()
}

fn render_markdown(
    scenario_id: &str,
    verdict: &str,
    rows: &[RowReport],
    dirty_blockers: &[DirtyBlocker],
    failure_reasons: &[String],
) -> String {
    let mut markdown = format!(
        "# Final Control-Loop Signoff: {scenario_id}\n\nVerdict: {verdict}\n\n| requirement_id | owner_bead | artifact | command_class | fallback_status |\n|---|---|---|---|---|\n"
    );
    for row in rows {
        markdown.push_str(&format!(
            "| {} | {} | {} | {} | {} |\n",
            row.row.requirement_id,
            row.row.owner_bead,
            row.row.artifact_path,
            row.row.command_class,
            row.row.fallback_status
        ));
    }
    if !dirty_blockers.is_empty() {
        markdown.push_str("\nDirty blockers:\n");
        for blocker in dirty_blockers {
            markdown.push_str(&format!(
                "- {}: {} ({})\n",
                blocker.blocker_id, blocker.path, blocker.retention_policy
            ));
        }
    }
    if !failure_reasons.is_empty() {
        markdown.push_str("\nFailures:\n");
        for reason in failure_reasons {
            markdown.push_str(&format!("- {reason}\n"));
        }
    }
    markdown
}

fn row_json(row: &RowReport) -> Value {
    json!({
        "requirement_id": row.row.requirement_id.clone(),
        "owner_bead": row.row.owner_bead.clone(),
        "artifact_path": row.row.artifact_path.clone(),
        "expected_artifact_sha256": row.expected_artifact_sha256.clone(),
        "observed_artifact_sha256": row.observed_artifact_sha256.clone(),
        "command_class": row.row.command_class.clone(),
        "proof_command": row.row.proof_command.clone(),
        "child_status": row.row.child_status.clone(),
        "fallback_status": row.row.fallback_status.clone(),
        "proxy_only": row.row.proxy_only,
    })
}

fn blocker_json(blocker: &DirtyBlocker) -> Value {
    json!({
        "blocker_id": blocker.blocker_id.clone(),
        "path": blocker.path.clone(),
        "blocker_type": blocker.blocker_type.clone(),
        "retention_policy": blocker.retention_policy.clone(),
        "fallback_reason": blocker.fallback_reason.clone(),
    })
}

fn report_json(report: &SignoffReport) -> Value {
    json!({
        "schema_version": report.schema_version.clone(),
        "scenario_id": report.scenario_id.clone(),
        "verdict": report.verdict.clone(),
        "accepted": report.accepted,
        "no_win": report.no_win,
        "parent_bead": report.parent_bead.clone(),
        "parent_expected_status": report.parent_expected_status.clone(),
        "child_row_count": report.child_row_count,
        "required_child_beads": report.required_child_beads.clone(),
        "no_win_rows": report.no_win_rows.clone(),
        "dirty_blockers": report.dirty_blockers.iter().map(blocker_json).collect::<Vec<_>>(),
        "certificate_artifacts": report.certificate_artifacts.clone(),
        "failure_reasons": report.failure_reasons.clone(),
        "first_failure": report.first_failure.clone(),
        "rows": report.rows.iter().map(row_json).collect::<Vec<_>>(),
        "signoff_digest_sha256": report.signoff_digest_sha256.clone(),
        "markdown": report.markdown.clone(),
    })
}

#[test]
fn final_signoff_manifest_parses_and_renders_expected_no_win() {
    let contract = contract();
    let scenario = &contract.smoke_scenarios[0];
    let report = evaluate(
        &contract,
        scenario,
        row_reports(&contract),
        dirty_blockers(&contract),
    );

    assert_eq!(contract.schema_version, SCHEMA_VERSION);
    assert_eq!(scenario.scenario_id, DEFAULT_SCENARIO_ID);
    assert_eq!(scenario.expected_verdict, report.verdict);
    assert_eq!(scenario.expected_child_rows, report.child_row_count);
    if let Some(expected_dirty_blockers) = scenario.expected_dirty_blockers {
        assert_eq!(expected_dirty_blockers, report.dirty_blockers.len());
    }
    assert_eq!(scenario.expected_no_win_rows, report.no_win_rows);
    assert!(!report.accepted);
    assert!(report.no_win);
    assert!(
        report.failure_reasons.is_empty(),
        "{:?}",
        report.failure_reasons
    );
    assert_eq!(report.signoff_digest_sha256.len(), 64);
}

#[test]
fn final_signoff_rejects_missing_child_rows() {
    let contract = contract();
    let scenario = &contract.smoke_scenarios[0];
    let mut rows = row_reports(&contract);
    rows.retain(|row| row.row.owner_bead != "asupersync-d87ytw.14");

    let report = evaluate(&contract, scenario, rows, dirty_blockers(&contract));

    assert_eq!(report.verdict, "fail_closed");
    assert!(
        report
            .failure_reasons
            .iter()
            .any(|reason| reason.contains("required child bead asupersync-d87ytw.14"))
    );
}

#[test]
fn final_signoff_rejects_stale_artifact_checksums() {
    let contract = contract();
    let scenario = &contract.smoke_scenarios[0];
    let mut rows = row_reports(&contract);
    rows[0].observed_artifact_sha256 = digest('0');

    let report = evaluate(&contract, scenario, rows, dirty_blockers(&contract));

    assert_eq!(report.verdict, "fail_closed");
    assert!(
        report
            .failure_reasons
            .iter()
            .any(|reason| reason.contains("artifact checksum mismatch"))
    );
}

#[test]
fn final_signoff_rejects_proxy_evidence() {
    let contract = contract();
    let scenario = &contract.smoke_scenarios[0];
    let mut rows = row_reports(&contract);
    rows[3].row.proxy_only = true;

    let report = evaluate(&contract, scenario, rows, dirty_blockers(&contract));

    assert_eq!(report.verdict, "fail_closed");
    assert!(
        report
            .failure_reasons
            .iter()
            .any(|reason| reason.contains("proxy-only"))
    );
}

#[test]
fn final_signoff_rejects_unsafe_dirty_retention() {
    let contract = contract();
    let scenario = &contract.smoke_scenarios[0];
    let mut blockers = dirty_blockers(&contract);
    blockers[0].retention_policy = "ignored".to_string();

    let report = evaluate(&contract, scenario, row_reports(&contract), blockers);

    assert_eq!(report.verdict, "fail_closed");
    assert!(
        report
            .failure_reasons
            .iter()
            .any(|reason| reason.contains("dirty blocker must block parent epic close"))
    );
}

#[test]
fn final_signoff_markdown_matches_json_rows() {
    let contract = contract();
    let scenario = &contract.smoke_scenarios[0];
    let report = evaluate(
        &contract,
        scenario,
        row_reports(&contract),
        dirty_blockers(&contract),
    );
    let json_report = report_json(&report);
    let markdown = json_report["markdown"].as_str().expect("markdown string");

    assert!(markdown.contains("Verdict: no_win"));
    for row in json_report["rows"].as_array().expect("rows array") {
        let requirement_id = row["requirement_id"].as_str().expect("requirement id");
        let owner_bead = row["owner_bead"].as_str().expect("owner bead");
        assert!(
            markdown.contains(requirement_id),
            "missing {requirement_id}"
        );
        assert!(markdown.contains(owner_bead), "missing {owner_bead}");
    }
}

#[test]
fn final_control_loop_signoff_smoke_emits_report() {
    let contract = contract();
    let scenario = &contract.smoke_scenarios[0];
    let report = evaluate(
        &contract,
        scenario,
        row_reports(&contract),
        dirty_blockers(&contract),
    );
    let json_report = report_json(&report);
    let report_path = std::env::var("ASUPERSYNC_FINAL_CONTROL_LOOP_SIGNOFF_REPORT_PATH").ok();
    let markdown_path = std::env::var("ASUPERSYNC_FINAL_CONTROL_LOOP_SIGNOFF_MARKDOWN_PATH").ok();

    if let Some(path) = report_path.as_deref() {
        let path = Path::new(path);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).expect("report parent dir");
        }
        fs::write(
            path,
            serde_json::to_string_pretty(&json_report).expect("report JSON"),
        )
        .expect("write final signoff report");
    }
    if let Some(path) = markdown_path.as_deref() {
        let path = Path::new(path);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).expect("markdown parent dir");
        }
        fs::write(path, &report.markdown).expect("write final signoff markdown");
    }

    println!(
        "ASUPERSYNC_FINAL_CONTROL_LOOP_SIGNOFF_JSON={}",
        serde_json::to_string(&json_report).expect("compact report JSON")
    );

    assert_eq!(report.verdict, "no_win");
    assert_eq!(report.child_row_count, 14);
    assert!(
        report
            .dirty_blockers
            .iter()
            .all(|blocker| blocker.retention_policy == "block_parent_epic_close")
    );
    assert!(
        report.failure_reasons.is_empty(),
        "{:?}",
        report.failure_reasons
    );
}
