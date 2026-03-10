//! Runtime ascension closure packet contract invariants (AA-10.3 prep).

#![allow(missing_docs)]

use serde_json::Value;
use std::collections::HashSet;
use std::path::PathBuf;
use std::process::Command;

const DOC_PATH: &str = "docs/runtime_ascension_closure_packet.md";
const ARTIFACT_PATH: &str = "artifacts/runtime_ascension_closure_packet_v1.json";
const RUNNER_PATH: &str = "scripts/run_runtime_ascension_closure_smoke.sh";

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn load_artifact() -> Value {
    let content = std::fs::read_to_string(repo_root().join(ARTIFACT_PATH))
        .expect("artifact must exist at expected path");
    serde_json::from_str(&content).expect("artifact must be valid JSON")
}

fn load_doc() -> String {
    std::fs::read_to_string(repo_root().join(DOC_PATH)).expect("contract doc must exist")
}

// ── Packet document ────────────────────────────────────────────────

#[test]
fn packet_doc_exists_and_has_required_sections() {
    let doc = load_doc();
    for section in &[
        "## Purpose",
        "## Contract Artifacts",
        "## Execution State",
        "## Current Decision Snapshot",
        "## Comparative Demo Matrix",
        "## Evidence Citation Registry",
        "## Default-Ready vs Experimental Surfaces",
        "## Known Risks, Non-Goals, and Downgrade Paths",
        "## Launch Doctrine",
        "## Operator/Developer Continuation Pack",
        "### Rerun Command Matrix",
        "## Validation",
        "## Cross-References",
    ] {
        assert!(doc.contains(section), "doc must contain section: {section}");
    }
}

#[test]
fn packet_doc_references_bead_and_parent() {
    let doc = load_doc();
    assert!(
        doc.contains("asupersync-1508v.10.6"),
        "doc must reference active owner bead id"
    );
    assert!(
        doc.contains("asupersync-1508v.10.6.2"),
        "doc must reference prep lineage bead id"
    );
    assert!(
        doc.contains("asupersync-1508v.10"),
        "doc must reference parent epic id"
    );
}

#[test]
fn packet_doc_declares_current_no_go() {
    let doc = load_doc();
    assert!(
        doc.contains("NO_GO"),
        "doc must state current NO_GO posture"
    );
    assert!(
        doc.contains("| Remaining blocker bead(s) | `none` |"),
        "doc must reflect that no external blocker beads remain"
    );
}

#[test]
fn packet_doc_mentions_registry_command_ids() {
    let doc = load_doc();
    for marker in &[
        "RACP-REFRESH-CLAIM-GRAPH",
        "RACP-VERIFY-STATIC-SAFETY-COMPILE-FAIL",
        "RACP-VERIFY-TRACE-INTELLIGENCE",
        "RACP-VERIFY-TRANSPORT-OPTIN",
        "RACP-VERIFY-WORKLOAD-CORPUS",
        "RACP-RUN-SMOKE-BUNDLE",
    ] {
        assert!(
            doc.contains(marker),
            "doc must mention command id: {marker}"
        );
    }
}

#[test]
fn packet_doc_mentions_runner_repo_root_determinism() {
    let doc = load_doc();
    assert!(
        doc.contains("repository root even when the script is invoked from another caller CWD"),
        "doc must explain repo-root execution behavior"
    );
    for required in &[
        "invoked_from",
        "command_workdir",
        "summary_file",
        "log_file",
    ] {
        assert!(
            doc.contains(required),
            "doc must mention provenance field {required}"
        );
    }
}

// ── Packet artifact ────────────────────────────────────────────────

#[test]
fn packet_artifact_has_contract_version() {
    let art = load_artifact();
    assert_eq!(
        art["contract_version"].as_str().unwrap(),
        "runtime-ascension-closure-packet-v1"
    );
    assert_eq!(
        art["bead_id"].as_str().unwrap(),
        "asupersync-1508v.10.6",
        "artifact bead_id must point to active owner bead"
    );
    let prep_beads = art["prep_bead_ids"]
        .as_array()
        .expect("prep_bead_ids must be an array");
    assert!(
        prep_beads
            .iter()
            .any(|bead| bead.as_str().unwrap() == "asupersync-1508v.10.6.2"),
        "artifact must reference prep lineage bead id"
    );
}

#[test]
fn packet_artifact_declares_execution_state() {
    let art = load_artifact();
    let state = &art["execution_state"];
    assert_eq!(
        state["phase"].as_str().unwrap(),
        "active_closure_execution",
        "execution_state.phase must reflect active closure execution"
    );
    assert_eq!(
        state["verdict"].as_str().unwrap(),
        "no_go",
        "execution_state.verdict must remain no_go while final sign-off is withheld"
    );
    let blockers = state["remaining_blockers"]
        .as_array()
        .expect("execution_state.remaining_blockers must be an array");
    assert!(
        blockers.is_empty(),
        "execution_state must show no remaining external blocker beads"
    );
}

#[test]
fn packet_artifact_has_runner_script() {
    let art = load_artifact();
    let runner = art["runner_script"].as_str().unwrap();
    assert_eq!(
        runner, RUNNER_PATH,
        "artifact must point at canonical runner"
    );
    assert!(
        repo_root().join(runner).exists(),
        "runner script must exist at {runner}"
    );
}

#[test]
fn packet_artifact_declares_runner_behavior_and_provenance_fields() {
    let art = load_artifact();
    let runner_behavior = &art["runner_behavior"];
    assert_eq!(
        runner_behavior["execution_root"].as_str().unwrap(),
        "project_root"
    );
    assert!(
        runner_behavior["caller_cwd_policy"]
            .as_str()
            .unwrap()
            .contains("caller CWD")
    );
    let fields: HashSet<&str> = runner_behavior["provenance_fields_required"]
        .as_array()
        .expect("runner provenance fields must be an array")
        .iter()
        .map(|value| value.as_str().unwrap())
        .collect();
    for required in &[
        "project_root",
        "invoked_from",
        "command",
        "command_workdir",
        "log_file",
        "summary_file",
    ] {
        assert!(
            fields.contains(required),
            "runner provenance fields must include {required}"
        );
    }
}

#[test]
fn packet_decision_snapshot_is_no_go_preparatory() {
    let art = load_artifact();
    let snapshot = &art["decision_snapshot"];
    assert_eq!(snapshot["overall_verdict"].as_str().unwrap(), "no_go");
    assert_eq!(snapshot["packet_mode"].as_str().unwrap(), "preparatory");
    let blockers = snapshot["blocking_beads"].as_array().unwrap();
    assert!(
        blockers.is_empty(),
        "decision snapshot must show no external blocker beads"
    );
}

#[test]
fn packet_closure_inputs_include_core_aa10_artifacts() {
    let art = load_artifact();
    let inputs = art["closure_inputs"].as_array().unwrap();
    let bead_ids: HashSet<&str> = inputs
        .iter()
        .map(|entry| entry["bead_id"].as_str().unwrap())
        .collect();
    for required in &[
        "asupersync-1508v.10.4",
        "asupersync-1508v.10.5",
        "asupersync-1508v.10.7",
        "asupersync-1508v.5.6",
        "asupersync-1508v.6.6",
        "asupersync-1508v.8.6",
    ] {
        assert!(
            bead_ids.contains(required),
            "closure inputs must include {required}"
        );
    }
}

// ── Demo matrix ────────────────────────────────────────────────────

#[test]
fn demo_definitions_are_nonempty() {
    let art = load_artifact();
    let demos = art["comparative_demos"].as_array().unwrap();
    assert!(demos.len() >= 4, "must define at least 4 comparative demos");
}

#[test]
fn demo_ids_are_unique() {
    let art = load_artifact();
    let demos = art["comparative_demos"].as_array().unwrap();
    let ids: Vec<&str> = demos
        .iter()
        .map(|d| d["demo_id"].as_str().unwrap())
        .collect();
    let mut deduped = ids.clone();
    deduped.sort_unstable();
    deduped.dedup();
    assert_eq!(ids.len(), deduped.len(), "demo_ids must be unique");
}

#[test]
fn demo_transport_optin_is_staged_after_transport_validation_closes() {
    let art = load_artifact();
    let demos = art["comparative_demos"].as_array().unwrap();
    let transport_demo = demos
        .iter()
        .find(|demo| demo["demo_id"].as_str().unwrap() == "DEMO-TRANSPORT-OPTIN")
        .unwrap();
    assert_eq!(transport_demo["status"].as_str().unwrap(), "staged");
    let blockers = transport_demo["blockers"].as_array().unwrap();
    assert!(
        blockers.is_empty(),
        "transport demo must no longer report AA-08 as an open blocker"
    );
    let evidence_refs: HashSet<&str> = transport_demo["evidence_refs"]
        .as_array()
        .unwrap()
        .iter()
        .map(|value| value.as_str().unwrap())
        .collect();
    assert!(
        evidence_refs.contains("artifacts/transport_frontier_benchmark_v1.json"),
        "transport demo must cite the closed transport validation artifact"
    );
}

#[test]
fn demo_every_definition_has_rerun_recipe() {
    let art = load_artifact();
    let demos = art["comparative_demos"].as_array().unwrap();
    for demo in demos {
        let id = demo["demo_id"].as_str().unwrap();
        let rerun = demo["rerun_recipe"].as_str().unwrap();
        assert!(!rerun.is_empty(), "{id}: rerun recipe must be non-empty");
    }
}

#[test]
fn evidence_registry_covers_every_demo_and_surface() {
    let art = load_artifact();
    let registry = art["evidence_registry"]
        .as_array()
        .expect("evidence_registry must be an array");
    let demo_ids: HashSet<&str> = art["comparative_demos"]
        .as_array()
        .unwrap()
        .iter()
        .map(|demo| demo["demo_id"].as_str().unwrap())
        .collect();
    let surface_ids: HashSet<&str> = art["surface_classification"]["surfaces"]
        .as_array()
        .unwrap()
        .iter()
        .map(|surface| surface["surface_id"].as_str().unwrap())
        .collect();

    let registry_demo_ids: HashSet<&str> = registry
        .iter()
        .filter(|entry| entry["scope_kind"].as_str().unwrap() == "demo")
        .map(|entry| entry["scope_id"].as_str().unwrap())
        .collect();
    let registry_surface_ids: HashSet<&str> = registry
        .iter()
        .filter(|entry| entry["scope_kind"].as_str().unwrap() == "surface")
        .map(|entry| entry["scope_id"].as_str().unwrap())
        .collect();

    assert_eq!(
        registry_demo_ids, demo_ids,
        "evidence registry must cover every comparative demo"
    );
    assert_eq!(
        registry_surface_ids, surface_ids,
        "evidence registry must cover every classified surface"
    );
}

#[test]
fn evidence_registry_command_ids_resolve_or_explain_blocked_gaps() {
    let art = load_artifact();
    let registry = art["evidence_registry"]
        .as_array()
        .expect("evidence_registry must be an array");
    let recipe_ids: HashSet<&str> = art["operator_recipes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|recipe| recipe["recipe_id"].as_str().unwrap())
        .collect();

    for entry in registry {
        let scope_id = entry["scope_id"].as_str().unwrap();
        let command_ids = entry["rerun_command_ids"]
            .as_array()
            .expect("rerun_command_ids must be an array");
        let blocked_by = entry["blocked_by"]
            .as_array()
            .expect("blocked_by must be an array");
        if command_ids.is_empty() {
            assert!(
                !blocked_by.is_empty(),
                "{scope_id}: empty command ids require an explicit blocker set"
            );
            let reason = entry["missing_command_reason"]
                .as_str()
                .expect("registry gaps must explain missing commands");
            assert!(
                !reason.is_empty(),
                "{scope_id}: missing_command_reason must be non-empty"
            );
        }
        for command_id in command_ids {
            let command_id = command_id.as_str().unwrap();
            assert!(
                recipe_ids.contains(command_id),
                "{scope_id}: unknown rerun command id {command_id}"
            );
        }
    }
}

#[test]
fn operator_recipe_ids_are_unique() {
    let art = load_artifact();
    let mut recipe_ids: Vec<&str> = art["operator_recipes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|recipe| recipe["recipe_id"].as_str().unwrap())
        .collect();
    let original_len = recipe_ids.len();
    recipe_ids.sort_unstable();
    recipe_ids.dedup();
    assert_eq!(recipe_ids.len(), original_len, "recipe_ids must be unique");
}

#[test]
fn smoke_runner_dry_run_records_repo_root_execution_and_provenance() {
    let repo = repo_root();
    let runner = repo.join(RUNNER_PATH);
    let scratch = tempfile::tempdir().expect("tempdir");
    let invoked_from = scratch.path().join("invoke-from");
    let output_root = scratch.path().join("out");
    std::fs::create_dir_all(&invoked_from).expect("invoke dir");

    let status = Command::new(&runner)
        .arg("--scenario")
        .arg("RACP-SMOKE-PACKET")
        .arg("--dry-run")
        .arg("--output-root")
        .arg(&output_root)
        .current_dir(&invoked_from)
        .status()
        .expect("failed to execute smoke runner");
    assert!(status.success(), "smoke runner dry-run must succeed");

    let run_dir = std::fs::read_dir(&output_root)
        .expect("output root must exist")
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .find(|path| path.is_dir())
        .expect("runner must emit a run directory");
    let run_report_path = run_dir.join("run_report.json");
    let bundle_manifest_path = run_dir
        .join("RACP-SMOKE-PACKET")
        .join("bundle_manifest.json");

    let report: Value = serde_json::from_str(
        &std::fs::read_to_string(&run_report_path).expect("run report must exist"),
    )
    .expect("run report must be valid JSON");
    let bundle: Value = serde_json::from_str(
        &std::fs::read_to_string(&bundle_manifest_path).expect("bundle manifest must exist"),
    )
    .expect("bundle manifest must be valid JSON");

    let repo_str = repo.to_string_lossy().into_owned();
    let invoked_from_str = invoked_from.to_string_lossy().into_owned();

    assert_eq!(report["project_root"].as_str().unwrap(), repo_str);
    assert_eq!(report["invoked_from"].as_str().unwrap(), invoked_from_str);
    assert_eq!(report["command_workdir"].as_str().unwrap(), repo_str);

    let results = report["results"].as_array().expect("results array");
    assert_eq!(results.len(), 1, "expected one selected scenario");
    let scenario_result = &results[0];
    assert_eq!(
        scenario_result["scenario_id"].as_str().unwrap(),
        "RACP-SMOKE-PACKET"
    );
    assert_eq!(scenario_result["project_root"].as_str().unwrap(), repo_str);
    assert_eq!(
        scenario_result["invoked_from"].as_str().unwrap(),
        invoked_from_str
    );
    assert_eq!(
        scenario_result["command_workdir"].as_str().unwrap(),
        repo_str
    );
    let scenario_command = scenario_result["command"].as_str().unwrap();
    assert!(
        scenario_command.contains("runtime_ascension_closure_packet_contract packet"),
        "scenario command must be captured in results"
    );

    let log_file = PathBuf::from(scenario_result["log_file"].as_str().unwrap());
    let summary_file = PathBuf::from(scenario_result["summary_file"].as_str().unwrap());
    assert!(log_file.exists(), "log file path must exist");
    assert!(summary_file.exists(), "summary file path must exist");

    assert_eq!(bundle["project_root"].as_str().unwrap(), repo_str);
    assert_eq!(bundle["invoked_from"].as_str().unwrap(), invoked_from_str);
    assert_eq!(bundle["command_workdir"].as_str().unwrap(), repo_str);
    assert_eq!(bundle["command"].as_str().unwrap(), scenario_command);
    assert_eq!(
        PathBuf::from(bundle["log_file"].as_str().unwrap()),
        log_file,
        "bundle must capture the same log file path as the aggregate report"
    );
    assert_eq!(
        PathBuf::from(bundle["summary_file"].as_str().unwrap()),
        summary_file,
        "bundle must capture the same summary file path as the aggregate report"
    );
}

// ── Launch doctrine ────────────────────────────────────────────────

#[test]
fn launch_surface_classification_has_default_ready_and_experimental_statuses() {
    let art = load_artifact();
    let statuses = art["surface_classification"]["status_definitions"]
        .as_object()
        .unwrap();
    for required in &["default_ready", "experimental", "blocked"] {
        assert!(
            statuses.contains_key(*required),
            "status definitions must include {required}"
        );
    }
}

#[test]
fn launch_transport_surface_is_experimental() {
    let art = load_artifact();
    let surfaces = art["surface_classification"]["surfaces"]
        .as_array()
        .unwrap();
    let transport = surfaces
        .iter()
        .find(|surface| surface["surface_id"].as_str().unwrap() == "AA-TRANSPORT-OPTIN")
        .unwrap();
    assert_eq!(transport["status"].as_str().unwrap(), "experimental");
}

#[test]
fn launch_packet_surface_is_blocked() {
    let art = load_artifact();
    let surfaces = art["surface_classification"]["surfaces"]
        .as_array()
        .unwrap();
    let packet = surfaces
        .iter()
        .find(|surface| surface["surface_id"].as_str().unwrap() == "AA-CLOSURE-PACKET")
        .unwrap();
    assert_eq!(packet["status"].as_str().unwrap(), "blocked");
}

#[test]
fn launch_doctrine_has_default_and_experimental_rules() {
    let art = load_artifact();
    let doctrine = &art["launch_doctrine"];
    for key in &[
        "default_ready_rules",
        "experimental_opt_in_rules",
        "incident_rules",
    ] {
        let rules = doctrine[*key].as_array().unwrap();
        assert!(!rules.is_empty(), "{key} must be non-empty");
    }
}

#[test]
fn launch_known_risks_have_downgrade_actions() {
    let art = load_artifact();
    let risks = art["known_risks"].as_array().unwrap();
    assert!(!risks.is_empty(), "known risks must be non-empty");
    for risk in risks {
        let risk_id = risk["risk_id"].as_str().unwrap();
        let action = risk["downgrade_action"].as_str().unwrap();
        assert!(
            !action.is_empty(),
            "{risk_id}: downgrade_action must be non-empty"
        );
    }
}

#[test]
fn launch_structured_log_fields_cover_packet_demo_and_downgrade() {
    let art = load_artifact();
    let fields = art["structured_log_fields_required"].as_array().unwrap();
    let field_set: HashSet<&str> = fields.iter().map(|value| value.as_str().unwrap()).collect();
    for required in &[
        "packet_id",
        "packet_verdict",
        "demo_id",
        "surface_id",
        "blocker_id",
        "rerun_command",
        "downgrade_action",
    ] {
        assert!(
            field_set.contains(required),
            "structured log fields must include {required}"
        );
    }
}

#[test]
fn launch_continuation_beads_include_parent_and_transport_blocker() {
    let art = load_artifact();
    let beads = art["continuation_beads"].as_array().unwrap();
    let bead_ids: HashSet<&str> = beads.iter().map(|b| b.as_str().unwrap()).collect();
    assert!(
        bead_ids.contains("asupersync-1508v.10.6"),
        "continuation set must include parent closure bead"
    );
    assert!(
        bead_ids.contains("asupersync-1508v.8"),
        "continuation set must include the experimental AA-08 transport track"
    );
}
