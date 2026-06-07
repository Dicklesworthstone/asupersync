#![allow(missing_docs)]

use serde_json::Value;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Command;

const SCRIPT_PATH: &str = "scripts/migration_readiness_planner.py";
const FIXTURE_ROOT: &str = "tests/fixtures/migration_readiness_planner";

fn repo_path(relative: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(relative)
}

fn repo_file_text(relative: &str) -> String {
    std::fs::read_to_string(repo_path(relative))
        .unwrap_or_else(|error| panic!("read {relative}: {error}"))
}

fn run_script(args: &[&str]) -> (std::process::ExitStatus, String, String) {
    let mut command = Command::new("python3");
    command.current_dir(repo_path("")).arg(SCRIPT_PATH);
    for arg in args {
        command.arg(arg);
    }
    let output = command.output().expect("run migration readiness planner");
    (
        output.status,
        String::from_utf8(output.stdout).expect("stdout utf8"),
        String::from_utf8(output.stderr).expect("stderr utf8"),
    )
}

fn run_planner(fixture: &str, extra_args: &[&str]) -> (std::process::ExitStatus, String, String) {
    let project_root = repo_path(&format!("{FIXTURE_ROOT}/{fixture}"));
    let project_root_arg = project_root.to_string_lossy().to_string();
    let mut args = vec!["--project-root", project_root_arg.as_str()];
    args.extend_from_slice(extra_args);
    run_script(&args)
}

fn json_report(fixture: &str) -> Value {
    let (status, stdout, stderr) = run_planner(fixture, &[]);
    assert!(
        status.success(),
        "planner failed for {fixture}: status={status:?} stderr={stderr}"
    );
    serde_json::from_str(&stdout).expect("planner stdout json")
}

fn rows(report: &Value) -> &[Value] {
    report["inventory_rows"]
        .as_array()
        .expect("inventory_rows array")
}

fn row_with_name<'a>(report: &'a Value, name: &str) -> &'a Value {
    rows(report)
        .iter()
        .find(|row| row["name"].as_str() == Some(name))
        .unwrap_or_else(|| panic!("missing row named {name}"))
}

fn proof_rows(report: &Value) -> &[Value] {
    report["proof_pack"]["quarantine_rows"]
        .as_array()
        .expect("proof_pack quarantine_rows array")
}

fn proof_row_with_name<'a>(report: &'a Value, name: &str) -> &'a Value {
    proof_rows(report)
        .iter()
        .find(|row| row["source_row"]["name"].as_str() == Some(name))
        .unwrap_or_else(|| panic!("missing proof row named {name}"))
}

fn proof_command_ids(report: &Value) -> Vec<&str> {
    report["proof_pack"]["proof_commands"]
        .as_array()
        .expect("proof command array")
        .iter()
        .map(|command| command["command_id"].as_str().expect("command id"))
        .collect()
}

fn semantic_recommendations(report: &Value) -> &[Value] {
    report["semantic_map"]["recommendations"]
        .as_array()
        .expect("semantic recommendations array")
}

fn semantic_row_with_class<'a>(report: &'a Value, recommendation_class: &str) -> &'a Value {
    semantic_recommendations(report)
        .iter()
        .find(|row| row["recommendation_class"].as_str() == Some(recommendation_class))
        .unwrap_or_else(|| panic!("missing semantic recommendation class {recommendation_class}"))
}

fn semantic_row_with_marker<'a>(report: &'a Value, marker: &str) -> &'a Value {
    semantic_recommendations(report)
        .iter()
        .find(|row| row["source_row"]["name"].as_str() == Some(marker))
        .unwrap_or_else(|| panic!("missing semantic recommendation for marker {marker}"))
}

fn operator_report(report: &Value) -> &Value {
    &report["operator_report"]
}

fn operator_phase_with_id<'a>(report: &'a Value, phase_id: &str) -> &'a Value {
    operator_report(report)["phase_plan"]
        .as_array()
        .expect("operator phase plan array")
        .iter()
        .find(|row| row["phase_id"].as_str() == Some(phase_id))
        .unwrap_or_else(|| panic!("missing operator phase {phase_id}"))
}

#[test]
fn native_fixture_reports_already_native_without_mutating_project() {
    let fixture_path = repo_path(&format!("{FIXTURE_ROOT}/native"));
    let before = std::fs::read_to_string(fixture_path.join("Cargo.toml")).expect("read fixture");
    let report = json_report("native");
    let after = std::fs::read_to_string(fixture_path.join("Cargo.toml")).expect("reread fixture");

    assert_eq!(before, after, "planner must not mutate scanned project");
    assert_eq!(report["schema_version"], "migration-readiness-inventory-v1");
    assert_eq!(
        report["read_only_contract"]["scanned_project_mutated"],
        false
    );
    assert_eq!(report["summary"]["final_verdict"], "ready");
    assert_eq!(
        report["proof_pack"]["summary"]["status"],
        "native_proof_ready"
    );
    assert_eq!(
        report["semantic_map"]["schema_version"],
        "migration-readiness-semantic-map-v1"
    );
    assert_eq!(
        report["semantic_map"]["summary"]["status"],
        "semantic_plan_ready"
    );
    assert_eq!(
        report["semantic_map"]["summary"]["recommendation_class_counts"]["compat_boundary_ok"],
        2
    );
    assert_eq!(
        operator_report(&report)["schema_version"],
        "migration-readiness-operator-report-v1"
    );
    assert_eq!(
        operator_report(&report)["summary"]["status"],
        "native_signoff_ready"
    );
    assert_eq!(operator_report(&report)["summary"]["phase_count"], 6);
    assert_eq!(
        operator_report(&report)["summary"]["residual_risk_count"],
        0
    );
    assert_eq!(operator_report(&report)["summary"]["confidence_score"], 100);
    assert_eq!(
        operator_phase_with_id(&report, "native-signoff-and-next-beads")["status"],
        "ready"
    );
    let summary_hash =
        operator_report(&report)["generation_log"]["input_artifact_hashes"]["summary"]
            .as_str()
            .expect("summary hash");
    assert_eq!(summary_hash.len(), 64, "hash should be hex sha256 length");
    let cx_signature = semantic_row_with_marker(&report, "async fn");
    assert_eq!(cx_signature["recommendation_class"], "compat_boundary_ok");
    assert_eq!(cx_signature["target_asupersync_surface"], "Cx");
    let proof_command_ids = proof_command_ids(&report);
    assert!(proof_command_ids.contains(&"default-production-tokio-tree"));
    assert!(proof_command_ids.contains(&"metrics-production-tokio-tree"));
    assert!(proof_command_ids.contains(&"fuzz-tokio-quarantine-tree"));
    for command in report["proof_pack"]["proof_commands"]
        .as_array()
        .expect("proof commands")
    {
        let command_text = command["command"].as_str().expect("proof command text");
        assert!(
            command_text.starts_with("RCH_REQUIRE_REMOTE=1 rch exec -- "),
            "proof commands must require remote rch: {command_text}"
        );
        assert!(
            command_text.contains("cargo tree"),
            "proof-pack command should be a cargo-tree graph proof"
        );
    }
    assert_eq!(
        row_with_name(&report, "asupersync")["classification"],
        "already_native"
    );
    assert!(
        report["warnings"]
            .as_array()
            .expect("warnings array")
            .iter()
            .any(|row| row["kind"] == "lockfile-missing"),
        "native fixture intentionally lacks Cargo.lock so the warning path is covered"
    );
}

#[test]
fn tokio_fixture_classifies_dependency_and_source_markers() {
    let report = json_report("tokio_service");

    assert_eq!(report["summary"]["final_verdict"], "needs_quarantine");
    assert_eq!(
        report["proof_pack"]["summary"]["status"],
        "compat_quarantine_required"
    );
    assert_eq!(
        row_with_name(&report, "tokio")["classification"],
        "runtime_boundary_required"
    );
    assert_eq!(
        row_with_name(&report, "axum")["classification"],
        "compat_quarantine_candidate"
    );
    assert!(
        rows(&report).iter().any(|row| {
            row["row_type"] == "source_marker"
                && row["marker"] == "tokio::spawn"
                && row["classification"] == "runtime_boundary_required"
        }),
        "tokio::spawn marker should be mapped to region-owned work guidance"
    );

    assert_eq!(
        report["semantic_map"]["summary"]["status"],
        "manual_design_required"
    );
    assert!(
        report["semantic_map"]["summary"]["source_match_count"]
            .as_u64()
            .expect("source match count")
            > 0
    );
    assert!(
        report["semantic_map"]["summary"]["residual_manual_design_count"]
            .as_u64()
            .expect("manual design count")
            > 0
    );
    for expected in [
        "cx_threading_required",
        "region_ownership_required",
        "cancel_checkpoint_required",
        "capability_narrowing_required",
        "compat_boundary_ok",
        "manual_design_required",
    ] {
        assert!(
            report["semantic_map"]["summary"]["recommendation_class_counts"][expected]
                .as_u64()
                .unwrap_or_default()
                > 0,
            "missing semantic recommendation class {expected}"
        );
    }
    let spawn = semantic_row_with_marker(&report, "tokio::spawn");
    assert_eq!(spawn["recommendation_class"], "region_ownership_required");
    assert_eq!(spawn["target_asupersync_surface"], "Scope");
    assert!(
        spawn["scenario_id"]
            .as_str()
            .expect("scenario id")
            .contains("tokio::spawn")
    );
    assert!(
        spawn["ordered_step"]
            .as_u64()
            .expect("ordered semantic step")
            > 0
    );
    assert_eq!(
        semantic_row_with_marker(&report, "tokio::time::sleep")["recommendation_class"],
        "cancel_checkpoint_required"
    );
    assert_eq!(
        semantic_row_with_marker(&report, "reqwest::Client")["recommendation_class"],
        "capability_narrowing_required"
    );
    assert_eq!(
        semantic_row_with_marker(&report, "axum::Router")["recommendation_class"],
        "compat_boundary_ok"
    );
    assert_eq!(
        semantic_row_with_class(&report, "manual_design_required")["residual_manual_design"],
        true
    );
    assert_eq!(
        operator_report(&report)["summary"]["status"],
        "manual_design_required"
    );
    assert!(
        operator_report(&report)["summary"]["highest_risk_score"]
            .as_u64()
            .expect("highest risk")
            >= 90
    );
    assert!(
        operator_report(&report)["summary"]["residual_risk_count"]
            .as_u64()
            .expect("risk count")
            > 0
    );
    assert_eq!(
        operator_report(&report)["executive_summary"]["recommended_next_action"],
        "follow-up:thread-cx-region-and-capabilities"
    );
    let cx_phase = operator_phase_with_id(&report, "thread-cx-region-and-capabilities");
    assert_eq!(cx_phase["status"], "pending");
    assert_eq!(cx_phase["risk_score"], 80);
    assert!(
        cx_phase["recommendation_classes"]
            .as_array()
            .expect("recommendation classes")
            .iter()
            .any(|class| class == "region_ownership_required")
    );
    let manual_phase = operator_phase_with_id(&report, "manual-ownership-design");
    assert_eq!(manual_phase["status"], "pending");
    assert_eq!(manual_phase["risk_score"], 90);
    let compat_phase = operator_phase_with_id(&report, "compat-quarantine-and-proof-pack");
    assert_eq!(compat_phase["status"], "pending");
    assert!(
        compat_phase["proof_command_ids"]
            .as_array()
            .expect("compat proof command ids")
            .iter()
            .any(|id| id == "default-production-tokio-tree")
    );

    let tokio_proof = proof_row_with_name(&report, "tokio");
    assert_eq!(
        tokio_proof["boundary_type"],
        "native_rewrite_or_compat_quarantine"
    );
    assert_eq!(tokio_proof["status"], "proof_commands_ready");
    let proof_ids = tokio_proof["proof_command_ids"]
        .as_array()
        .expect("tokio proof command ids");
    for expected in [
        "default-production-tokio-tree",
        "metrics-production-tokio-tree",
        "workspace-normal-tokio-audit",
        "full-feature-tokio-audit",
    ] {
        assert!(
            proof_ids.iter().any(|id| id == expected),
            "tokio proof row missing {expected}"
        );
    }
    assert!(
        proof_command_ids(&report).contains(&"fuzz-tokio-quarantine-tree"),
        "proof command catalog should distinguish fuzz-only tokio quarantine"
    );
}

#[test]
fn malformed_manifest_fails_closed_and_can_exit_nonzero() {
    let report = json_report("malformed");

    assert_eq!(report["summary"]["final_verdict"], "blocked");
    assert!(
        report["summary"]["fail_closed_reasons"]
            .as_array()
            .expect("fail_closed_reasons array")
            .iter()
            .any(|reason| reason == "manifest-parse-error")
    );
    assert_eq!(report["proof_pack"]["summary"]["status"], "blocked");
    assert_eq!(report["semantic_map"]["summary"]["status"], "blocked");
    assert_eq!(operator_report(&report)["summary"]["status"], "blocked");
    let preflight = operator_phase_with_id(&report, "preflight-and-input-integrity");
    assert_eq!(preflight["status"], "blocked");
    assert_eq!(preflight["risk_score"], 100);
    assert!(
        operator_report(&report)["residual_risk_rows"]
            .as_array()
            .expect("operator residual risks")
            .iter()
            .any(|row| row["risk_id"] == "fail-closed:manifest-parse-error")
    );
    assert!(
        report["proof_pack"]["fail_closed_reasons"]
            .as_array()
            .expect("proof fail_closed_reasons array")
            .iter()
            .any(|reason| reason == "inventory-report-blocked")
    );
    assert!(
        report["semantic_map"]["fail_closed_reasons"]
            .as_array()
            .expect("semantic fail_closed_reasons array")
            .iter()
            .any(|reason| reason == "inventory-report-blocked")
    );

    let (status, stdout, _stderr) = run_planner("malformed", &["--fail-on-blocked"]);
    assert_eq!(status.code(), Some(2));
    let failed_report: Value = serde_json::from_str(&stdout).expect("blocked stdout json");
    assert_eq!(failed_report["summary"]["final_verdict"], "blocked");
}

#[test]
fn workspace_fixture_records_feature_gated_and_transitive_rows() {
    let report = json_report("workspace");

    assert_eq!(report["summary"]["manifest_count"], 2);
    assert_eq!(report["lockfile"]["status"], "present");
    let tokio = row_with_name(&report, "tokio");
    assert_eq!(tokio["classification"], "runtime_boundary_required");
    assert_eq!(tokio["optional"], true);
    assert_eq!(tokio["feature_gated"], true);
    assert!(
        rows(&report).iter().any(|row| {
            row["row_type"] == "lockfile_package"
                && row["name"] == "hyper"
                && row["classification"] == "compat_quarantine_candidate"
        }),
        "Cargo.lock should surface transitive runtime packages not declared directly"
    );
    let hyper_proof = proof_row_with_name(&report, "hyper");
    assert_eq!(
        hyper_proof["source_row"]["source_kind"],
        "transitive_lockfile_package"
    );
    assert_eq!(hyper_proof["boundary_type"], "compat_quarantine");
    assert!(
        report["semantic_map"]["summary"]["recommendation_count"]
            .as_u64()
            .expect("semantic recommendation count")
            > 0
    );
    assert!(
        report["semantic_map"]["summary"]["confidence_distribution"]
            .as_object()
            .expect("confidence distribution")
            .contains_key("high")
    );
    assert!(
        operator_report(&report)["summary"]["proof_command_count"]
            .as_u64()
            .expect("proof command count")
            >= 5
    );
}

#[test]
fn output_root_writes_json_and_summary_artifacts() {
    let temp_dir = tempfile::tempdir().expect("tempdir");
    let output_root = temp_dir.path().join("planner-output");
    let output_arg = output_root.to_string_lossy().to_string();
    let (status, stdout, stderr) = run_planner("tokio_service", &["--output-root", &output_arg]);
    assert!(status.success(), "planner failed: {stderr}");
    let report: Value = serde_json::from_str(&stdout).expect("stdout json");

    let json_path = output_root.join("migration_readiness_inventory.json");
    let summary_path = output_root.join("migration_readiness_summary.md");
    assert!(json_path.exists(), "json artifact missing");
    assert!(summary_path.exists(), "summary artifact missing");
    let artifact_report: Value =
        serde_json::from_str(&std::fs::read_to_string(&json_path).expect("read json artifact"))
            .expect("artifact json");
    assert_eq!(artifact_report["summary"], report["summary"]);
    assert_eq!(
        artifact_report["operator_report"],
        report["operator_report"]
    );
    assert_eq!(
        report["operator_report"]["generation_log"]["generated_output_paths"]["json"],
        json_path.to_string_lossy().as_ref()
    );
    let summary = std::fs::read_to_string(summary_path).expect("read summary");
    assert!(summary.contains("Migration Readiness Inventory"));
    assert!(summary.contains("Operator Report"));
    assert!(summary.contains("Phase Plan"));
    assert!(summary.contains("risk_score=`90`"));
    assert!(summary.contains("Residual Risks"));
    assert!(summary.contains("Proof Pack"));
    assert!(summary.contains("Semantic Map"));
    assert!(summary.contains("needs_quarantine"));
    assert!(summary.contains("manual_design_required"));
    assert!(summary.contains("default-production-tokio-tree"));
}

fn e2e_result_with_id<'a>(report: &'a Value, scenario_id: &str) -> &'a Value {
    report["scenario_results"]
        .as_array()
        .expect("scenario results array")
        .iter()
        .find(|row| row["scenario_id"].as_str() == Some(scenario_id))
        .unwrap_or_else(|| panic!("missing e2e scenario {scenario_id}"))
}

#[test]
fn e2e_list_reports_expected_fixture_scenarios() {
    let (status, stdout, stderr) = run_script(&["--list"]);
    assert!(status.success(), "list failed: {stderr}");
    let catalog: Value = serde_json::from_str(&stdout).expect("scenario catalog json");

    assert_eq!(
        catalog["schema_version"],
        "migration-readiness-e2e-scenario-catalog-v1"
    );
    let ids: BTreeSet<&str> = catalog["scenarios"]
        .as_array()
        .expect("scenarios array")
        .iter()
        .map(|row| row["scenario_id"].as_str().expect("scenario id"))
        .collect();
    for expected in [
        "native-clean",
        "tokio-http-service",
        "mixed-compat-boundary",
        "malformed-workspace",
        "feature-gated-tokio-edge",
        "blocked-ambient-authority-service",
        "zero-evidence-empty",
    ] {
        assert!(ids.contains(expected), "missing scenario {expected}");
    }
}

#[test]
fn e2e_dry_run_selects_scenarios_without_writing_artifacts() {
    let temp_dir = tempfile::tempdir().expect("tempdir");
    let output_root = temp_dir.path().join("dry-run-output");
    let output_arg = output_root.to_string_lossy().to_string();
    let (status, stdout, stderr) = run_script(&[
        "--dry-run",
        "--scenario",
        "native-clean",
        "--scenario",
        "malformed-workspace",
        "--output-root",
        &output_arg,
    ]);
    assert!(status.success(), "dry-run failed: {stderr}");
    assert!(
        !output_root.exists(),
        "dry-run must not create the requested output root"
    );
    let report: Value = serde_json::from_str(&stdout).expect("dry-run json");
    assert_eq!(report["schema_version"], "migration-readiness-e2e-proof-v1");
    assert_eq!(report["mode"], "dry_run");
    assert_eq!(report["summary"]["overall_status"], "dry_run");
    assert_eq!(report["summary"]["scenario_count"], 2);
    for scenario_id in ["native-clean", "malformed-workspace"] {
        let result = e2e_result_with_id(&report, scenario_id);
        assert_eq!(result["status"], "planned");
        assert_eq!(result["generated_artifacts"].as_object().unwrap().len(), 0);
        assert_eq!(
            result["pipeline_stage_log"][1]["stage"], "dry_run",
            "dry-run should log the skipped execution stage"
        );
    }
}

#[test]
fn e2e_unknown_scenario_fails_without_traceback() {
    let (status, stdout, stderr) = run_script(&["--list", "--scenario", "missing-scenario"]);

    assert_eq!(status.code(), Some(2));
    assert!(stdout.is_empty(), "unknown scenario should not emit stdout");
    assert!(stderr.contains("unknown scenario id(s): missing-scenario"));
    assert!(!stderr.contains("Traceback"));
}

#[test]
fn e2e_execute_writes_artifacts_and_validates_all_scenarios() {
    let temp_dir = tempfile::tempdir().expect("tempdir");
    let output_root = temp_dir.path().join("e2e-output");
    let output_arg = output_root.to_string_lossy().to_string();
    let (status, stdout, stderr) = run_script(&["--execute", "--output-root", &output_arg]);
    assert!(status.success(), "execute failed: {stderr}");
    let report: Value = serde_json::from_str(&stdout).expect("execute json");

    assert_eq!(report["schema_version"], "migration-readiness-e2e-proof-v1");
    assert_eq!(report["mode"], "execute");
    assert_eq!(report["summary"]["overall_status"], "passed");
    assert_eq!(report["summary"]["scenario_count"], 7);
    assert_eq!(report["summary"]["failed_count"], 0);
    assert!(
        output_root
            .join("migration_readiness_e2e_report.json")
            .exists()
    );
    assert!(
        output_root
            .join("migration_readiness_e2e_summary.md")
            .exists()
    );
    assert_eq!(
        report["output_artifacts"]["json"],
        output_root
            .join("migration_readiness_e2e_report.json")
            .to_string_lossy()
            .as_ref()
    );

    for (scenario_id, final_verdict, operator_status) in [
        ("native-clean", "ready", "native_signoff_ready"),
        (
            "tokio-http-service",
            "needs_quarantine",
            "manual_design_required",
        ),
        (
            "mixed-compat-boundary",
            "needs_quarantine",
            "quarantine_plan_ready",
        ),
        ("malformed-workspace", "blocked", "blocked"),
        (
            "feature-gated-tokio-edge",
            "needs_quarantine",
            "quarantine_plan_ready",
        ),
        ("blocked-ambient-authority-service", "blocked", "blocked"),
        ("zero-evidence-empty", "blocked", "blocked"),
    ] {
        let result = e2e_result_with_id(&report, scenario_id);
        assert_eq!(result["status"], "passed", "scenario {scenario_id}");
        assert_eq!(result["final_verdict"], final_verdict);
        assert_eq!(result["operator_status"], operator_status);
        assert_eq!(result["proof_command_count"], 5);
        assert_eq!(
            result["fixture_hash"].as_str().expect("fixture hash").len(),
            64
        );
        assert_eq!(
            result["generated_artifact_hashes"]["json_sha256"]
                .as_str()
                .expect("json artifact hash")
                .len(),
            64
        );
        assert_eq!(
            result["generated_artifact_hashes"]["summary_sha256"]
                .as_str()
                .expect("summary artifact hash")
                .len(),
            64
        );
        let artifacts = result["generated_artifacts"]
            .as_object()
            .expect("generated artifacts");
        for path in artifacts.values() {
            assert!(
                Path::new(path.as_str().expect("artifact path")).exists(),
                "scenario artifact should exist for {scenario_id}: {path}"
            );
        }
        let stages: BTreeSet<&str> = result["pipeline_stage_log"]
            .as_array()
            .expect("stage log")
            .iter()
            .map(|row| row["stage"].as_str().expect("stage"))
            .collect();
        for stage in [
            "fixture_hash",
            "build_report",
            "write_outputs",
            "validate_expectations",
        ] {
            assert!(
                stages.contains(stage),
                "scenario {scenario_id} missing stage {stage}"
            );
        }
    }

    assert!(
        e2e_result_with_id(&report, "zero-evidence-empty")["fail_closed_reasons"]
            .as_array()
            .expect("zero evidence fail reasons")
            .iter()
            .any(|reason| reason == "zero-runtime-surface-evidence")
    );
    assert!(
        e2e_result_with_id(&report, "blocked-ambient-authority-service")["classification_counts"]
            ["hard_blocker"]
            .as_u64()
            .expect("hard blocker count")
            > 0
    );
    let summary = std::fs::read_to_string(output_root.join("migration_readiness_e2e_summary.md"))
        .expect("read e2e summary");
    assert!(summary.contains("Migration Readiness E2E Proof"));
    assert!(summary.contains("mixed-compat-boundary"));
    assert!(summary.contains("zero-evidence-empty"));
}

#[test]
fn planner_docs_surfaces_keep_entrypoints_and_report_markers() {
    let readme = repo_file_text("README.md");
    let integration = repo_file_text("docs/integration.md");
    let mega_skill = repo_file_text("skills/asupersync-mega-skill/SKILL.md");

    for marker in [
        "scripts/migration_readiness_planner.py",
        "docs/integration.md#migration-readiness-planner",
        "--project-root",
        "--output-root",
        "summary.final_verdict",
        "proof_pack.proof_commands",
        "semantic_map.recommendations",
        "operator_report.phase_plan",
    ] {
        assert!(readme.contains(marker), "README missing marker {marker}");
    }

    for marker in [
        "Migration Readiness Planner",
        "scripts/migration_readiness_planner.py",
        "--list",
        "--dry-run",
        "--execute",
        "--project-root",
        "native-clean",
        "tokio-http-service",
        "mixed-compat-boundary",
        "malformed-workspace",
        "feature-gated-tokio-edge",
        "blocked-ambient-authority-service",
        "zero-evidence-empty",
        "summary.final_verdict",
        "proof_pack.proof_commands",
        "semantic_map.recommendations",
        "operator_report.phase_plan",
        "operator_report.residual_risks",
        "default-production-tokio-tree",
        "metrics-production-tokio-tree",
        "fuzz-tokio-quarantine-tree",
    ] {
        assert!(
            integration.contains(marker),
            "integration docs missing marker {marker}"
        );
    }

    for marker in [
        "scripts/migration_readiness_planner.py",
        "--project-root",
        "--dry-run",
        "--execute",
        "summary.final_verdict",
        "proof_pack.proof_commands",
        "semantic_map.recommendations",
        "operator_report.phase_plan",
    ] {
        assert!(
            mega_skill.contains(marker),
            "mega-skill missing marker {marker}"
        );
    }
}
