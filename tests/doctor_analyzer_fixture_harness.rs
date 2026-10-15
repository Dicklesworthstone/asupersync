#![allow(warnings)]
#![allow(clippy::all)]
#![allow(missing_docs)]
#![cfg(feature = "cli")]

use asupersync::cli::doctor::{
    DOCTOR_EVIDENCE_SCHEMA_VERSION, DoctorEvidenceBundle, DoctorEvidenceFinding, RuntimeArtifact,
    analyze_doctor_evidence_report, analyze_workspace_invariants,
    analyze_workspace_lock_contention, emit_lock_contention_structured_events,
    ingest_doctor_evidence_bundle, scan_workspace, structured_logging_contract,
    validate_doctor_evidence_analysis_report, validate_doctor_evidence_bundle,
    validate_evidence_ingestion_report, validate_structured_logging_event_stream,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use tempfile::TempDir;

const FIXTURE_PACK_PATH: &str = "tests/fixtures/doctor_analyzer_harness/fixtures.json";
const FIXTURE_PACK_SCHEMA_VERSION: &str = "doctor-analyzer-fixture-pack-v1";

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
struct FixturePack {
    schema_version: String,
    fixtures: Vec<AnalyzerFixture>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
struct AnalyzerFixture {
    fixture_id: String,
    description: String,
    family: AnalyzerFamily,
    workspace_root: Option<String>,
    artifact_profile: Option<String>,
    expectation: FixtureExpectation,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum AnalyzerFamily {
    Scanner,
    Invariant,
    LockContention,
    Ingestion,
    EvidenceAnalysis,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
struct FixtureExpectation {
    min_members: Option<usize>,
    min_edges: Option<usize>,
    min_warnings: Option<usize>,
    warning_contains: Option<Vec<String>>,
    min_findings: Option<usize>,
    min_hotspots: Option<usize>,
    min_violations: Option<usize>,
    min_records: Option<usize>,
    min_rejected: Option<usize>,
    min_recipe_suggestions: Option<usize>,
    expected_families: Option<Vec<String>>,
    expected_risk_classes: Option<Vec<String>>,
    expected_asup_codes: Option<Vec<String>>,
    repro_command: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct FixtureExecutionLog {
    fixture_id: String,
    family: String,
    status: String,
    run_id: String,
    scenario_id: String,
    seed: String,
    repro_command: String,
    diagnostics: Vec<String>,
    metrics: BTreeMap<String, String>,
}

fn load_fixture_pack() -> FixturePack {
    let path = repo_root().join(FIXTURE_PACK_PATH);
    let raw = fs::read_to_string(&path).expect("read fixture pack");
    let pack: FixturePack = serde_json::from_str(&raw).expect("parse fixture pack");
    assert_eq!(
        pack.schema_version, FIXTURE_PACK_SCHEMA_VERSION,
        "unexpected fixture-pack schema version"
    );
    assert!(
        !pack.fixtures.is_empty(),
        "fixture pack must contain at least one fixture"
    );
    pack
}

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn fixture_path(relative: &str) -> PathBuf {
    repo_root().join(relative)
}

fn copy_fixture_tree(src: &Path, dst: &Path) {
    fs::create_dir_all(dst).expect("create staged fixture dir");
    for entry in fs::read_dir(src).expect("read fixture dir") {
        let entry = entry.expect("read fixture entry");
        let src_path = entry.path();
        let dst_path = dst.join(entry.file_name());
        let file_type = entry.file_type().expect("fixture file type");
        if file_type.is_dir() {
            copy_fixture_tree(&src_path, &dst_path);
        } else {
            fs::copy(&src_path, &dst_path).expect("copy fixture file");
        }
    }
}

fn stage_workspace_fixture(relative: &str) -> (Option<TempDir>, PathBuf) {
    if relative != "tests/fixtures/doctor_workspace_scan_e2e" {
        return (None, fixture_path(relative));
    }

    let temp_dir = tempfile::tempdir().expect("fixture temp dir");
    let staged_root = temp_dir.path().join("doctor_workspace_scan_e2e");
    copy_fixture_tree(&fixture_path(relative), &staged_root);
    fs::write(
        staged_root.join("beta/Cargo.toml"),
        r#"[package]
name = beta
version = "0.1.0"
edition = "2024"
"#,
    )
    .expect("write malformed staged beta manifest");
    (Some(temp_dir), staged_root)
}

fn mixed_artifacts_fixture() -> Vec<RuntimeArtifact> {
    vec![
        RuntimeArtifact {
            artifact_id: "artifact-001".to_string(),
            artifact_type: "trace".to_string(),
            source_path: "artifacts/trace-001.json".to_string(),
            replay_pointer: "asupersync trace verify artifacts/trace-001.bin".to_string(),
            content: r#"{
                "correlation_id": "corr-001",
                "scenario_id": "fixture-scenario",
                "seed": "0xABCD",
                "outcome_class": "success",
                "summary": "trace replay completed"
            }"#
            .to_string(),
        },
        RuntimeArtifact {
            artifact_id: "artifact-002".to_string(),
            artifact_type: "structured_log".to_string(),
            source_path: "artifacts/log-002.json".to_string(),
            replay_pointer: "asupersync doctor logging-contract --json".to_string(),
            content: r#"{
                "trace_id": "trace-002",
                "scenario_id": "fixture-scenario",
                "seed": "0xABCD",
                "outcome": "failed",
                "message": "lock-order warning"
            }"#
            .to_string(),
        },
        RuntimeArtifact {
            artifact_id: "artifact-003".to_string(),
            artifact_type: "ubs_findings".to_string(),
            source_path: "artifacts/ubs-003.txt".to_string(),
            replay_pointer: "ubs src/cli/doctor/mod.rs".to_string(),
            content: "src/cli/doctor/mod.rs:10:5 issue-A\nsrc/cli/doctor/mod.rs:20:7 issue-B"
                .to_string(),
        },
        RuntimeArtifact {
            artifact_id: "artifact-004".to_string(),
            artifact_type: "unsupported".to_string(),
            source_path: "artifacts/unknown-004.bin".to_string(),
            replay_pointer: "none".to_string(),
            content: "unsupported payload".to_string(),
        },
    ]
}

fn source_adapter_matrix_fixture() -> Vec<RuntimeArtifact> {
    vec![
        RuntimeArtifact {
            artifact_id: "browser-package".to_string(),
            artifact_type: "browser_package_readiness".to_string(),
            source_path: "docs/wasm_browser_artifact_integrity_manifest_v1.json".to_string(),
            replay_pointer: "bash scripts/build_browser_core_artifacts.sh prod".to_string(),
            content: r#"{
                "correlation_id": "browser-package",
                "scenario_id": "browser-ga",
                "seed": "none",
                "outcome_class": "success",
                "summary": "browser package manifest verified"
            }"#
            .to_string(),
        },
        RuntimeArtifact {
            artifact_id: "cargo-graph".to_string(),
            artifact_type: "cargo_feature_graph".to_string(),
            source_path: "target/cargo-tree/default.txt".to_string(),
            replay_pointer: "rch exec -- cargo tree -e normal -p asupersync".to_string(),
            content: "asupersync v0.3.4\nserde v1.0.0\n".to_string(),
        },
        RuntimeArtifact {
            artifact_id: "proof-lane".to_string(),
            artifact_type: "proof_lane_manifest".to_string(),
            source_path: "artifacts/proof_lane_manifest_v1.json".to_string(),
            replay_pointer: "rch exec -- cargo test --test proof_lane_manifest_contract"
                .to_string(),
            content: r#"{
                "correlation_id": "proof-lane",
                "scenario_id": "proof-manifest",
                "seed": "none",
                "outcome_class": "success",
                "summary": "manifest row parsed"
            }"#
            .to_string(),
        },
        RuntimeArtifact {
            artifact_id: "proof-status".to_string(),
            artifact_type: "proof_status".to_string(),
            source_path: "artifacts/proof_status_snapshot_v1.json".to_string(),
            replay_pointer: "rch exec -- cargo test --test proof_status_snapshot_contract"
                .to_string(),
            content: r#"{
                "correlation_id": "proof-status",
                "scenario_id": "proof-status",
                "seed": "none",
                "outcome_class": "success",
                "summary": "snapshot row parsed"
            }"#
            .to_string(),
        },
        RuntimeArtifact {
            artifact_id: "rch-preflight".to_string(),
            artifact_type: "rch_receipt".to_string(),
            source_path: "target/rch/topology-preflight.json".to_string(),
            replay_pointer: "RCH_REQUIRE_REMOTE=1 rch exec -- cargo test ...".to_string(),
            content: r#"{
                "correlation_id": "rch-preflight",
                "scenario_id": "topology-preflight",
                "seed": "none",
                "outcome_class": "failed",
                "summary": "remote topology preflight failed before Cargo"
            }"#
            .to_string(),
        },
        RuntimeArtifact {
            artifact_id: "redacted-log".to_string(),
            artifact_type: "redacted_log".to_string(),
            source_path: "logs/doctor-redacted.json".to_string(),
            replay_pointer: "asupersync doctor collect-logs --redact".to_string(),
            content: r#"{
                "correlation_id": "redacted-log",
                "scenario_id": "doctor-log",
                "seed": "none",
                "outcome_class": "success",
                "summary": "token=[REDACTED]"
            }"#
            .to_string(),
        },
        RuntimeArtifact {
            artifact_id: "runtime-inspector".to_string(),
            artifact_type: "runtime_inspector".to_string(),
            source_path: "target/runtime-inspector/snapshot.json".to_string(),
            replay_pointer: "asupersync doctor runtime-inspector --json".to_string(),
            content: r#"{
                "correlation_id": "runtime-inspector",
                "scenario_id": "runtime-health",
                "seed": "none",
                "outcome_class": "success",
                "summary": "runtime inspector snapshot parsed"
            }"#
            .to_string(),
        },
        RuntimeArtifact {
            artifact_id: "tracker-context".to_string(),
            artifact_type: "tracker_context".to_string(),
            source_path: ".beads/issues.jsonl".to_string(),
            replay_pointer: "br show asupersync-idea-wizard-fifth-wave-3gaiun.1.1 --json"
                .to_string(),
            content: r#"{
                "correlation_id": "tracker-context",
                "scenario_id": "doctor-d1",
                "seed": "none",
                "outcome_class": "success",
                "summary": "bead context parsed"
            }"#
            .to_string(),
        },
        RuntimeArtifact {
            artifact_id: "unredacted-log".to_string(),
            artifact_type: "redacted_log".to_string(),
            source_path: "logs/raw.json".to_string(),
            replay_pointer: "asupersync doctor collect-logs".to_string(),
            content: r#"{
                "correlation_id": "raw-log",
                "scenario_id": "doctor-log",
                "seed": "none",
                "outcome_class": "failed",
                "summary": "UNREDACTED_SECRET token leaked"
            }"#
            .to_string(),
        },
    ]
}

fn evidence_analysis_d2_matrix_fixture() -> Vec<RuntimeArtifact> {
    vec![
        RuntimeArtifact {
            artifact_id: "browser-unsupported-host".to_string(),
            artifact_type: "browser_package_readiness".to_string(),
            source_path: "artifacts/browser-readiness.json".to_string(),
            replay_pointer: "rch exec -- cargo test -p asupersync-browser-core".to_string(),
            content: r#"{
                "correlation_id": "browser-unsupported-host",
                "scenario_id": "doctor-d2-browser",
                "seed": "none",
                "outcome_class": "failed",
                "summary": "unsupported host for wasm browser package"
            }"#
            .to_string(),
        },
        RuntimeArtifact {
            artifact_id: "futurelock-detected".to_string(),
            artifact_type: "trace".to_string(),
            source_path: "artifacts/futurelock-trace.json".to_string(),
            replay_pointer: "rch exec -- cargo test --features test-internals lab futurelock"
                .to_string(),
            content: r#"{
                "correlation_id": "futurelock-detected",
                "scenario_id": "doctor-d2-futurelock",
                "seed": "0xFUTURE",
                "outcome_class": "failed",
                "summary": "ASUP-E402 futurelock detected no possible progress in parked set"
            }"#
            .to_string(),
        },
        RuntimeArtifact {
            artifact_id: "local-fallback-marker".to_string(),
            artifact_type: "proof_status".to_string(),
            source_path: "artifacts/proof-status-local.json".to_string(),
            replay_pointer:
                "RCH_REQUIRE_REMOTE=1 rch exec -- cargo check -p asupersync --features cli --lib"
                    .to_string(),
            content: r#"{
                "correlation_id": "local-fallback-marker",
                "scenario_id": "doctor-d2-local-fallback",
                "seed": "none",
                "outcome_class": "failed",
                "summary": "no-local-fallback violation: local fallback marker location=local"
            }"#
            .to_string(),
        },
        RuntimeArtifact {
            artifact_id: "missing-proof-artifact".to_string(),
            artifact_type: "proof_lane_manifest".to_string(),
            source_path: "artifacts/proof_lane_manifest_v1.json".to_string(),
            replay_pointer: "rch exec -- cargo test --test proof_lane_manifest_contract"
                .to_string(),
            content: r#"{
                "correlation_id": "missing-proof-artifact",
                "scenario_id": "doctor-d2-missing-proof",
                "seed": "none",
                "outcome_class": "failed",
                "summary": "missing proof artifact for manifest lane doctor-d2"
            }"#
            .to_string(),
        },
        RuntimeArtifact {
            artifact_id: "obligation-leak".to_string(),
            artifact_type: "runtime_inspector".to_string(),
            source_path: "artifacts/runtime-obligation.json".to_string(),
            replay_pointer: "rch exec -- cargo test --features test-internals obligation"
                .to_string(),
            content: r#"{
                "correlation_id": "obligation-leak",
                "scenario_id": "doctor-d2-obligation",
                "seed": "none",
                "outcome_class": "failed",
                "summary": "ASUP-E101 obligation leak: permit leak in channel reserve path"
            }"#
            .to_string(),
        },
        RuntimeArtifact {
            artifact_id: "proof-artifact-rejected".to_string(),
            artifact_type: "proof_status".to_string(),
            source_path: "artifacts/proof-status-malformed.json".to_string(),
            replay_pointer: "rch exec -- cargo test --test proof_status_snapshot_contract"
                .to_string(),
            content: "not-json".to_string(),
        },
        RuntimeArtifact {
            artifact_id: "region-close-timeout".to_string(),
            artifact_type: "runtime_inspector".to_string(),
            source_path: "artifacts/runtime-region-close.json".to_string(),
            replay_pointer: "rch exec -- cargo test --features test-internals cancel drain"
                .to_string(),
            content: r#"{
                "correlation_id": "region-close-timeout",
                "scenario_id": "doctor-d2-region-close",
                "seed": "none",
                "outcome_class": "failed",
                "summary": "ASUP-E301 region-close timeout while waiting for child drain"
            }"#
            .to_string(),
        },
        RuntimeArtifact {
            artifact_id: "stale-docs-claim".to_string(),
            artifact_type: "tracker_context".to_string(),
            source_path: ".beads/issues.jsonl".to_string(),
            replay_pointer: "br show asupersync-idea-wizard-fifth-wave-3gaiun.1.2 --json"
                .to_string(),
            content: r#"{
                "correlation_id": "stale-docs-claim",
                "scenario_id": "doctor-d2-docs-claim",
                "seed": "none",
                "outcome_class": "failed",
                "summary": "stale docs claim for proof-status snapshot"
            }"#
            .to_string(),
        },
        RuntimeArtifact {
            artifact_id: "stale-rch-proof".to_string(),
            artifact_type: "rch_receipt".to_string(),
            source_path: "artifacts/rch-stale-progress.json".to_string(),
            replay_pointer:
                "RCH_REQUIRE_REMOTE=1 rch exec -- cargo test -p asupersync --features cli --test doctor_analyzer_fixture_harness"
                    .to_string(),
            content: r#"{
                "correlation_id": "stale-rch-proof",
                "scenario_id": "doctor-d2-rch",
                "seed": "none",
                "outcome_class": "failed",
                "summary": "heartbeat live but progress-stale stuck_detector cancelled proof"
            }"#
            .to_string(),
        },
    ]
}

fn doctor_evidence_bundle(
    run_id: &str,
    source_profile: &str,
    artifacts: Vec<RuntimeArtifact>,
) -> DoctorEvidenceBundle {
    DoctorEvidenceBundle {
        schema_version: DOCTOR_EVIDENCE_SCHEMA_VERSION.to_string(),
        bundle_id: format!("bundle-{run_id}"),
        run_id: run_id.to_string(),
        source_profile: source_profile.to_string(),
        generated_by: "doctor-analyzer-fixture-harness".to_string(),
        artifacts,
    }
}

#[allow(clippy::too_many_lines)]
fn execute_fixture(fixture: &AnalyzerFixture) -> FixtureExecutionLog {
    let run_id = format!("run-{}", fixture.fixture_id);
    let scenario_id = fixture.fixture_id.clone();
    let seed = "0xD0C70R".to_string();
    let mut diagnostics = Vec::new();
    let mut metrics = BTreeMap::new();

    match fixture.family {
        AnalyzerFamily::Scanner => {
            let workspace_root = fixture
                .workspace_root
                .as_deref()
                .expect("scanner fixture requires workspace_root");
            let (_staged_fixture, workspace_root) = stage_workspace_fixture(workspace_root);
            let report = scan_workspace(&workspace_root).expect("scan workspace");
            let report_again = scan_workspace(&workspace_root).expect("scan workspace (repeat)");
            if report != report_again {
                diagnostics
                    .push("scanner report is non-deterministic across repeated run".to_string());
            }
            metrics.insert("member_count".to_string(), report.members.len().to_string());
            metrics.insert(
                "edge_count".to_string(),
                report.capability_edges.len().to_string(),
            );
            metrics.insert(
                "warning_count".to_string(),
                report.warnings.len().to_string(),
            );
            apply_scanner_expectations(
                &fixture.expectation,
                &report.warnings,
                &metrics,
                &mut diagnostics,
            );
        }
        AnalyzerFamily::Invariant => {
            let workspace_root = fixture
                .workspace_root
                .as_deref()
                .expect("invariant fixture requires workspace_root");
            let (_staged_fixture, workspace_root) = stage_workspace_fixture(workspace_root);
            let scan_report = scan_workspace(&workspace_root).expect("scan workspace");
            let analysis = analyze_workspace_invariants(&scan_report);
            let analysis_again = analyze_workspace_invariants(&scan_report);
            if analysis != analysis_again {
                diagnostics.push("invariant analyzer report is non-deterministic".to_string());
            }
            metrics.insert(
                "member_count".to_string(),
                analysis.member_count.to_string(),
            );
            metrics.insert(
                "finding_count".to_string(),
                analysis.finding_count.to_string(),
            );
            metrics.insert(
                "rule_trace_count".to_string(),
                analysis.rule_traces.len().to_string(),
            );
            apply_numeric_expectation(
                fixture.expectation.min_members,
                analysis.member_count,
                "member_count",
                &mut diagnostics,
            );
            apply_numeric_expectation(
                fixture.expectation.min_findings,
                analysis.finding_count,
                "finding_count",
                &mut diagnostics,
            );
        }
        AnalyzerFamily::LockContention => {
            let workspace_root = fixture
                .workspace_root
                .as_deref()
                .expect("lock-contention fixture requires workspace_root");
            let scan_report =
                scan_workspace(&fixture_path(workspace_root)).expect("scan workspace");
            let analysis = analyze_workspace_lock_contention(&scan_report);
            let analysis_again = analyze_workspace_lock_contention(&scan_report);
            if analysis != analysis_again {
                diagnostics
                    .push("lock-contention analyzer report is non-deterministic".to_string());
            }
            let events = emit_lock_contention_structured_events(&analysis, &run_id, &scenario_id)
                .expect("emit structured events");
            validate_structured_logging_event_stream(&structured_logging_contract(), &events)
                .expect("validate structured lock-contention events");
            metrics.insert(
                "member_count".to_string(),
                analysis.member_count.to_string(),
            );
            metrics.insert(
                "hotspot_count".to_string(),
                analysis.hotspot_count.to_string(),
            );
            metrics.insert(
                "violation_count".to_string(),
                analysis.violation_count.to_string(),
            );
            metrics.insert(
                "structured_event_count".to_string(),
                events.len().to_string(),
            );
            apply_numeric_expectation(
                fixture.expectation.min_members,
                analysis.member_count,
                "member_count",
                &mut diagnostics,
            );
            apply_numeric_expectation(
                fixture.expectation.min_hotspots,
                analysis.hotspot_count,
                "hotspot_count",
                &mut diagnostics,
            );
            apply_numeric_expectation(
                fixture.expectation.min_violations,
                analysis.violation_count,
                "violation_count",
                &mut diagnostics,
            );
        }
        AnalyzerFamily::Ingestion => {
            let profile = fixture
                .artifact_profile
                .as_deref()
                .expect("ingestion fixture requires artifact_profile");
            let artifacts = match profile {
                "mixed_artifacts_v1" => mixed_artifacts_fixture(),
                "source_adapter_matrix_v1" => source_adapter_matrix_fixture(),
                "evidence_analysis_d2_matrix_v1" => evidence_analysis_d2_matrix_fixture(),
                other => panic!("unsupported artifact profile {other}"),
            };
            let bundle = doctor_evidence_bundle(&run_id, profile, artifacts);
            validate_doctor_evidence_bundle(&bundle).expect("doctor evidence bundle validates");
            let report = ingest_doctor_evidence_bundle(&bundle);
            let report_again = ingest_doctor_evidence_bundle(&bundle);
            if report != report_again {
                diagnostics.push("ingestion report is non-deterministic".to_string());
            }
            validate_evidence_ingestion_report(&report).expect("ingestion report validates");
            metrics.insert("record_count".to_string(), report.records.len().to_string());
            metrics.insert(
                "rejected_count".to_string(),
                report.rejected.len().to_string(),
            );
            metrics.insert("event_count".to_string(), report.events.len().to_string());
            apply_numeric_expectation(
                fixture.expectation.min_records,
                report.records.len(),
                "record_count",
                &mut diagnostics,
            );
            apply_numeric_expectation(
                fixture.expectation.min_rejected,
                report.rejected.len(),
                "rejected_count",
                &mut diagnostics,
            );
        }
        AnalyzerFamily::EvidenceAnalysis => {
            let profile = fixture
                .artifact_profile
                .as_deref()
                .expect("evidence-analysis fixture requires artifact_profile");
            let artifacts = match profile {
                "evidence_analysis_d2_matrix_v1" => evidence_analysis_d2_matrix_fixture(),
                other => panic!("unsupported artifact profile {other}"),
            };
            let bundle = doctor_evidence_bundle(&run_id, profile, artifacts);
            validate_doctor_evidence_bundle(&bundle).expect("doctor evidence bundle validates");
            let ingestion_report = ingest_doctor_evidence_bundle(&bundle);
            validate_evidence_ingestion_report(&ingestion_report)
                .expect("ingestion report validates");
            let analysis = analyze_doctor_evidence_report(&ingestion_report);
            let analysis_again = analyze_doctor_evidence_report(&ingestion_report);
            if analysis != analysis_again {
                diagnostics.push("evidence analyzer report is non-deterministic".to_string());
            }
            validate_doctor_evidence_analysis_report(&analysis)
                .expect("evidence analysis report validates");
            let recipe_suggestion_count = analysis
                .findings
                .iter()
                .filter(|finding| finding.remediation_recipe.is_some())
                .count();
            metrics.insert(
                "finding_count".to_string(),
                analysis.finding_count.to_string(),
            );
            metrics.insert(
                "record_count".to_string(),
                ingestion_report.records.len().to_string(),
            );
            metrics.insert(
                "recipe_suggestion_count".to_string(),
                recipe_suggestion_count.to_string(),
            );
            metrics.insert(
                "rejected_count".to_string(),
                ingestion_report.rejected.len().to_string(),
            );
            apply_numeric_expectation(
                fixture.expectation.min_findings,
                analysis.finding_count,
                "finding_count",
                &mut diagnostics,
            );
            apply_numeric_expectation(
                fixture.expectation.min_records,
                ingestion_report.records.len(),
                "record_count",
                &mut diagnostics,
            );
            apply_numeric_expectation(
                fixture.expectation.min_rejected,
                ingestion_report.rejected.len(),
                "rejected_count",
                &mut diagnostics,
            );
            apply_numeric_expectation(
                fixture.expectation.min_recipe_suggestions,
                recipe_suggestion_count,
                "recipe_suggestion_count",
                &mut diagnostics,
            );
            apply_evidence_analysis_expectations(
                &fixture.expectation,
                &analysis.findings,
                &mut diagnostics,
            );
        }
    }

    FixtureExecutionLog {
        fixture_id: fixture.fixture_id.clone(),
        family: fixture_family_name(&fixture.family).to_string(),
        status: if diagnostics.is_empty() {
            "pass".to_string()
        } else {
            "fail".to_string()
        },
        run_id,
        scenario_id,
        seed,
        repro_command: fixture.expectation.repro_command.clone(),
        diagnostics,
        metrics,
    }
}

fn fixture_family_name(family: &AnalyzerFamily) -> &'static str {
    match family {
        AnalyzerFamily::Scanner => "scanner",
        AnalyzerFamily::Invariant => "invariant",
        AnalyzerFamily::LockContention => "lock_contention",
        AnalyzerFamily::Ingestion => "ingestion",
        AnalyzerFamily::EvidenceAnalysis => "evidence_analysis",
    }
}

fn apply_numeric_expectation(
    minimum: Option<usize>,
    actual: usize,
    label: &str,
    diagnostics: &mut Vec<String>,
) {
    if let Some(minimum) = minimum {
        if actual < minimum {
            diagnostics.push(format!(
                "{label} below expected minimum: actual={actual} expected>={minimum}"
            ));
        }
    }
}

fn apply_scanner_expectations(
    expectation: &FixtureExpectation,
    warnings: &[String],
    metrics: &BTreeMap<String, String>,
    diagnostics: &mut Vec<String>,
) {
    let member_count = metrics
        .get("member_count")
        .and_then(|count| count.parse::<usize>().ok())
        .expect("member_count metric is parseable");
    let edge_count = metrics
        .get("edge_count")
        .and_then(|count| count.parse::<usize>().ok())
        .expect("edge_count metric is parseable");
    let warning_count = metrics
        .get("warning_count")
        .and_then(|count| count.parse::<usize>().ok())
        .expect("warning_count metric is parseable");
    apply_numeric_expectation(
        expectation.min_members,
        member_count,
        "member_count",
        diagnostics,
    );
    apply_numeric_expectation(expectation.min_edges, edge_count, "edge_count", diagnostics);
    apply_numeric_expectation(
        expectation.min_warnings,
        warning_count,
        "warning_count",
        diagnostics,
    );
    if let Some(tokens) = &expectation.warning_contains {
        let flattened = warnings.join(" | ").to_lowercase();
        for token in tokens {
            if !flattened.contains(&token.to_lowercase()) {
                diagnostics.push(format!("warning corpus missing token `{token}`"));
            }
        }
    }
}

fn apply_evidence_analysis_expectations(
    expectation: &FixtureExpectation,
    findings: &[DoctorEvidenceFinding],
    diagnostics: &mut Vec<String>,
) {
    if let Some(expected_families) = &expectation.expected_families {
        let observed_families = findings
            .iter()
            .map(|finding| finding.diagnostic_family.as_str())
            .collect::<BTreeSet<_>>();
        for family in expected_families {
            if !observed_families.contains(family.as_str()) {
                diagnostics.push(format!("missing evidence diagnostic family `{family}`"));
            }
        }
    }

    if let Some(expected_risk_classes) = &expectation.expected_risk_classes {
        let observed_risk_classes = findings
            .iter()
            .filter_map(|finding| finding.remediation_recipe.as_ref())
            .map(|recipe| recipe.risk_class.as_str())
            .collect::<BTreeSet<_>>();
        for risk_class in expected_risk_classes {
            if !observed_risk_classes.contains(risk_class.as_str()) {
                diagnostics.push(format!("missing remediation risk class `{risk_class}`"));
            }
        }
    }

    if let Some(expected_asup_codes) = &expectation.expected_asup_codes {
        let observed_asup_codes = findings
            .iter()
            .filter_map(|finding| finding.asup_error_code.as_deref())
            .collect::<Vec<_>>()
            .join(" | ");
        for code in expected_asup_codes {
            if !observed_asup_codes.contains(code) {
                diagnostics.push(format!("missing ASUP code pointer `{code}`"));
            }
        }
    }
}

fn run_all_fixtures(pack: &FixturePack) -> Vec<FixtureExecutionLog> {
    let mut logs: Vec<FixtureExecutionLog> = pack.fixtures.iter().map(execute_fixture).collect();
    logs.sort_by(|left, right| left.fixture_id.cmp(&right.fixture_id));
    logs
}

fn run_fixture_by_id(pack: &FixturePack, fixture_id: &str) -> FixtureExecutionLog {
    let fixture = pack
        .fixtures
        .iter()
        .find(|fixture| fixture.fixture_id == fixture_id)
        .unwrap_or_else(|| panic!("missing fixture {fixture_id}"));
    execute_fixture(fixture)
}

#[test]
fn fixture_loader_is_deterministic() {
    let first = load_fixture_pack();
    let second = load_fixture_pack();
    assert_eq!(first, second, "fixture loader should be deterministic");
}

#[test]
fn analyzer_fixture_harness_e2e_suite_is_deterministic() {
    let pack = load_fixture_pack();
    let first_logs = run_all_fixtures(&pack);
    let second_logs = run_all_fixtures(&pack);
    assert_eq!(
        first_logs, second_logs,
        "fixture harness execution should be deterministic"
    );
    assert!(
        first_logs.iter().all(|log| log.status == "pass"),
        "fixture harness failures: {}",
        serde_json::to_string_pretty(&first_logs).expect("serialize harness logs")
    );
}

#[test]
fn ingestion_source_adapter_matrix() {
    let pack = load_fixture_pack();
    let log = run_fixture_by_id(&pack, "ingestion_source_adapter_matrix");
    assert_eq!(
        log.status,
        "pass",
        "fixture failed: {}",
        serde_json::to_string_pretty(&log).expect("serialize fixture log")
    );
    assert_eq!(
        log.metrics.get("record_count").map(String::as_str),
        Some("9")
    );
    assert_eq!(
        log.metrics.get("rejected_count").map(String::as_str),
        Some("1")
    );
}

#[test]
fn evidence_analysis_d2_matrix() {
    let pack = load_fixture_pack();
    let log = run_fixture_by_id(&pack, "evidence_analysis_d2_matrix");
    assert_eq!(
        log.status,
        "pass",
        "fixture failed: {}",
        serde_json::to_string_pretty(&log).expect("serialize fixture log")
    );
    assert_eq!(
        log.metrics.get("finding_count").map(String::as_str),
        Some("9")
    );
    assert_eq!(
        log.metrics
            .get("recipe_suggestion_count")
            .map(String::as_str),
        Some("9")
    );
}

#[test]
fn structured_fixture_logs_include_repro_commands_and_diagnostics() {
    let pack = load_fixture_pack();
    let logs = run_all_fixtures(&pack);
    for log in &logs {
        assert!(
            !log.repro_command.trim().is_empty(),
            "fixture log must include repro command: {}",
            log.fixture_id
        );
        assert!(
            !log.run_id.trim().is_empty() && !log.scenario_id.trim().is_empty(),
            "fixture log must include run/scenario provenance: {}",
            log.fixture_id
        );
        assert!(
            !log.metrics.is_empty(),
            "fixture log must include metrics payload: {}",
            log.fixture_id
        );
    }
    let encoded = serde_json::to_string(&logs).expect("serialize structured logs");
    assert!(
        encoded.contains("\"repro_command\"") && encoded.contains("\"metrics\""),
        "structured log payload must retain repro + metrics fields"
    );
}
