#![allow(clippy::all)]
//! Transport frontier feasibility harness and benchmark contract invariants (AA-08.1).

#![allow(missing_docs)]

use serde_json::Value;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

const DOC_PATH: &str = "docs/transport_frontier_benchmark_contract.md";
const ARTIFACT_PATH: &str = "artifacts/transport_frontier_benchmark_v1.json";
const RUNNER_SCRIPT_PATH: &str = "scripts/run_transport_frontier_benchmark_smoke.sh";

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn load_doc() -> String {
    std::fs::read_to_string(repo_root().join(DOC_PATH))
        .expect("failed to load transport frontier doc")
}

fn load_artifact() -> Value {
    let raw = std::fs::read_to_string(repo_root().join(ARTIFACT_PATH))
        .expect("failed to load transport frontier artifact");
    serde_json::from_str(&raw).expect("failed to parse artifact")
}

// ── Doc existence and structure ──────────────────────────────────────

#[test]
fn doc_exists() {
    assert!(Path::new(DOC_PATH).exists(), "doc must exist");
}

#[test]
fn doc_references_bead() {
    let doc = load_doc();
    assert!(
        doc.contains("asupersync-1508v.8.4"),
        "doc must reference bead id"
    );
}

#[test]
fn doc_has_required_sections() {
    let doc = load_doc();
    let sections = [
        "Purpose",
        "Contract Artifacts",
        "Current Transport Substrate",
        "Benchmark Dimensions",
        "Workload Vocabulary",
        "Experiment Catalog",
        "Structured Logging Contract",
        "Comparator-Smoke Runner",
        "Validation",
        "Cross-References",
    ];
    let mut missing = Vec::new();
    for section in sections {
        if !doc.contains(section) {
            missing.push(section);
        }
    }
    assert!(
        missing.is_empty(),
        "doc missing sections:\n{}",
        missing
            .iter()
            .map(|s| format!("  - {s}"))
            .collect::<Vec<_>>()
            .join("\n")
    );
}

#[test]
fn doc_references_artifact_runner_and_test() {
    let doc = load_doc();
    for reference in [
        "artifacts/transport_frontier_benchmark_v1.json",
        "scripts/run_transport_frontier_benchmark_smoke.sh",
        "tests/transport_frontier_benchmark_contract.rs",
        "src/transport/aggregator.rs",
        "src/transport/mock.rs",
    ] {
        assert!(doc.contains(reference), "doc must reference {reference}");
    }
}

#[test]
fn doc_reproduction_command_uses_rch() {
    let doc = load_doc();
    assert!(
        doc.contains(
            "rch exec -- env CARGO_INCREMENTAL=0 CARGO_TARGET_DIR=/tmp/rch-codex-aa081 cargo test --test transport_frontier_benchmark_contract -- --nocapture"
        ),
        "doc must route heavy validation through rch"
    );
}

// ── Artifact schema and version stability ────────────────────────────

#[test]
fn artifact_versions_are_stable() {
    let artifact = load_artifact();
    assert_eq!(
        artifact["contract_version"].as_str(),
        Some("transport-frontier-benchmark-v1")
    );
    assert_eq!(
        artifact["runner_bundle_schema_version"].as_str(),
        Some("transport-frontier-benchmark-smoke-bundle-v1")
    );
    assert_eq!(
        artifact["runner_report_schema_version"].as_str(),
        Some("transport-frontier-benchmark-smoke-run-report-v1")
    );
    assert_eq!(
        artifact["runner_suite_summary_schema_version"].as_str(),
        Some("transport-frontier-benchmark-smoke-suite-summary-v1")
    );
}

#[test]
fn runner_bundle_required_fields_are_stable() {
    let artifact = load_artifact();
    let actual: BTreeSet<String> = artifact["runner_bundle_required_fields"]
        .as_array()
        .expect("runner_bundle_required_fields must be array")
        .iter()
        .map(|field| field.as_str().expect("field must be string").to_string())
        .collect();
    let expected: BTreeSet<String> = [
        "schema",
        "scenario_id",
        "description",
        "workload_id",
        "validation_surface",
        "focus_dimension_ids",
        "run_id",
        "mode",
        "command",
        "timestamp",
        "artifact_path",
        "runner_script",
        "bundle_manifest_path",
        "planned_run_log_path",
        "planned_run_report_path",
        "rch_routed",
    ]
    .into_iter()
    .map(ToOwned::to_owned)
    .collect();
    assert_eq!(actual, expected, "bundle schema fields must remain stable");
}

#[test]
fn runner_report_required_fields_are_stable() {
    let artifact = load_artifact();
    let actual: BTreeSet<String> = artifact["runner_report_required_fields"]
        .as_array()
        .expect("runner_report_required_fields must be array")
        .iter()
        .map(|field| field.as_str().expect("field must be string").to_string())
        .collect();
    let expected: BTreeSet<String> = [
        "schema",
        "scenario_id",
        "description",
        "workload_id",
        "validation_surface",
        "focus_dimension_ids",
        "run_id",
        "mode",
        "command",
        "artifact_path",
        "runner_script",
        "bundle_manifest_path",
        "run_log_path",
        "run_report_path",
        "output_dir",
        "rch_routed",
        "started_at",
        "finished_at",
        "exit_code",
    ]
    .into_iter()
    .map(ToOwned::to_owned)
    .collect();
    assert_eq!(actual, expected, "report schema fields must remain stable");
}

#[test]
fn runner_suite_summary_required_fields_are_stable() {
    let artifact = load_artifact();
    let actual: BTreeSet<String> = artifact["runner_suite_summary_required_fields"]
        .as_array()
        .expect("runner_suite_summary_required_fields must be array")
        .iter()
        .map(|field| field.as_str().expect("field must be string").to_string())
        .collect();
    let expected: BTreeSet<String> = [
        "schema",
        "run_id",
        "mode",
        "artifact_path",
        "runner_script",
        "output_dir",
        "summary_path",
        "started_at",
        "finished_at",
        "status",
        "scenario_count",
        "scenario_ids",
        "all_rch_routed",
        "suite_exit_code",
        "scenarios",
    ]
    .into_iter()
    .map(ToOwned::to_owned)
    .collect();
    assert_eq!(
        actual, expected,
        "suite summary schema fields must remain stable"
    );
}

#[test]
fn runner_suite_summary_scenario_fields_are_stable() {
    let artifact = load_artifact();
    let actual: BTreeSet<String> = artifact["runner_suite_summary_scenario_required_fields"]
        .as_array()
        .expect("runner_suite_summary_scenario_required_fields must be array")
        .iter()
        .map(|field| field.as_str().expect("field must be string").to_string())
        .collect();
    let expected: BTreeSet<String> = [
        "scenario_id",
        "description",
        "workload_id",
        "validation_surface",
        "focus_dimension_ids",
        "command",
        "output_dir",
        "bundle_manifest_path",
        "run_log_path",
        "run_report_path",
        "status",
        "exit_code",
        "rch_routed",
    ]
    .into_iter()
    .map(ToOwned::to_owned)
    .collect();
    assert_eq!(
        actual, expected,
        "suite summary scenario entry fields must remain stable"
    );
}

// ── Transport component inventory ────────────────────────────────────

#[test]
fn transport_components_have_expected_ids() {
    let artifact = load_artifact();
    let actual: BTreeSet<String> = artifact["transport_components"]
        .as_array()
        .expect("transport_components must be array")
        .iter()
        .map(|c| c["component_id"].as_str().unwrap().to_string())
        .collect();
    let expected: BTreeSet<String> = [
        "symbol-sink-stream",
        "multipath-aggregator",
        "routing-dispatch",
        "sim-network",
    ]
    .into_iter()
    .map(ToOwned::to_owned)
    .collect();
    assert_eq!(actual, expected);
}

#[test]
fn transport_component_owner_files_exist() {
    let artifact = load_artifact();
    let root = repo_root();
    for component in artifact["transport_components"].as_array().unwrap() {
        let cid = component["component_id"].as_str().unwrap();
        for owner in component["owner_files"].as_array().unwrap() {
            let path = owner.as_str().unwrap();
            assert!(
                root.join(path).exists(),
                "owner file for {cid} must exist: {path}"
            );
        }
    }
}

// ── Benchmark dimensions ─────────────────────────────────────────────

#[test]
fn benchmark_dimensions_have_expected_ids() {
    let artifact = load_artifact();
    let actual: BTreeSet<String> = artifact["benchmark_dimensions"]
        .as_array()
        .expect("benchmark_dimensions must be array")
        .iter()
        .map(|d| d["dimension_id"].as_str().unwrap().to_string())
        .collect();
    let expected: BTreeSet<String> = [
        "rtt-tail-latency",
        "goodput-under-loss",
        "fairness",
        "cpu-per-packet",
        "failure-handling",
        "operator-visibility",
    ]
    .into_iter()
    .map(ToOwned::to_owned)
    .collect();
    assert_eq!(actual, expected, "benchmark dimensions must remain stable");
}

#[test]
fn each_dimension_has_metrics() {
    let artifact = load_artifact();
    for dim in artifact["benchmark_dimensions"].as_array().unwrap() {
        let did = dim["dimension_id"].as_str().unwrap();
        let metrics = dim["metrics"].as_array().expect("metrics must be array");
        assert!(!metrics.is_empty(), "dimension {did} must have metrics");
    }
}

// ── Workload vocabulary ──────────────────────────────────────────────

#[test]
fn workload_vocabulary_has_expected_ids() {
    let artifact = load_artifact();
    let actual: BTreeSet<String> = artifact["workload_vocabulary"]
        .as_array()
        .expect("workload_vocabulary must be array")
        .iter()
        .map(|w| w["workload_id"].as_str().unwrap().to_string())
        .collect();
    let expected: BTreeSet<String> = [
        "TW-BURST",
        "TW-REORDER",
        "TW-HANDOFF",
        "TW-OVERLOAD",
        "TW-MULTIPATH",
        "TW-FAIRNESS",
    ]
    .into_iter()
    .map(ToOwned::to_owned)
    .collect();
    assert_eq!(actual, expected, "workload vocabulary must remain stable");
}

#[test]
fn each_workload_has_required_fields() {
    let artifact = load_artifact();
    for workload in artifact["workload_vocabulary"].as_array().unwrap() {
        let wid = workload["workload_id"].as_str().unwrap_or("<missing>");
        for field in ["workload_id", "description", "pattern"] {
            assert!(
                workload.get(field).is_some(),
                "workload {wid} missing field: {field}"
            );
        }
    }
}

// ── Experiment catalog ───────────────────────────────────────────────

#[test]
fn experiment_catalog_has_expected_ids() {
    let artifact = load_artifact();
    let actual: BTreeSet<String> = artifact["experiments"]
        .as_array()
        .expect("experiments must be array")
        .iter()
        .map(|e| e["experiment_id"].as_str().unwrap().to_string())
        .collect();
    let expected: BTreeSet<String> = [
        "receiver-driven-rpc",
        "multipath-transport",
        "coded-transport",
    ]
    .into_iter()
    .map(ToOwned::to_owned)
    .collect();
    assert_eq!(actual, expected, "experiment catalog must remain stable");
}

#[test]
fn each_experiment_has_required_fields() {
    let artifact = load_artifact();
    for experiment in artifact["experiments"].as_array().unwrap() {
        let eid = experiment["experiment_id"].as_str().unwrap_or("<missing>");
        for field in [
            "experiment_id",
            "description",
            "hypothesis",
            "key_dimensions",
        ] {
            assert!(
                experiment.get(field).is_some(),
                "experiment {eid} missing field: {field}"
            );
        }
    }
}

#[test]
fn experiment_key_dimensions_reference_valid_dims() {
    let artifact = load_artifact();
    let dim_ids: BTreeSet<String> = artifact["benchmark_dimensions"]
        .as_array()
        .unwrap()
        .iter()
        .map(|d| d["dimension_id"].as_str().unwrap().to_string())
        .collect();

    for experiment in artifact["experiments"].as_array().unwrap() {
        let eid = experiment["experiment_id"].as_str().unwrap();
        for dim in experiment["key_dimensions"].as_array().unwrap() {
            let dim_id = dim.as_str().unwrap();
            assert!(
                dim_ids.contains(dim_id),
                "experiment {eid} references unknown dimension: {dim_id}"
            );
        }
    }
}

// ── Structured log fields ────────────────────────────────────────────

#[test]
fn structured_log_fields_are_unique_and_nonempty() {
    let artifact = load_artifact();
    let fields = artifact["structured_log_fields_required"]
        .as_array()
        .expect("structured_log_fields_required must be array");
    assert!(!fields.is_empty());
    let mut set = BTreeSet::new();
    for field in fields {
        let f = field.as_str().expect("field must be string").to_string();
        assert!(!f.is_empty());
        assert!(set.insert(f.clone()), "duplicate field: {f}");
    }
}

#[test]
fn structured_log_contract_mentions_transport_decision_metadata() {
    let doc = load_doc();
    for field in [
        "benchmark_correlation_id",
        "path_count",
        "experimental_gate_id",
        "path_policy_id",
        "effective_path_policy_id",
        "requested_path_count",
        "selected_path_count",
        "fallback_path_count",
        "selected_path_ids",
        "fallback_path_ids",
        "fallback_policy_id",
        "path_downgrade_reason",
        "downgrade_reason",
        "coding_policy_id",
        "effective_coding_policy_id",
    ] {
        assert!(
            doc.contains(field),
            "doc must mention structured log field {field}"
        );
    }
}

#[test]
fn structured_log_fields_include_transport_decision_metadata() {
    let artifact = load_artifact();
    let fields: BTreeSet<String> = artifact["structured_log_fields_required"]
        .as_array()
        .expect("structured_log_fields_required must be array")
        .iter()
        .map(|field| field.as_str().expect("field must be string").to_string())
        .collect();

    for field in [
        "benchmark_correlation_id",
        "path_count",
        "experimental_gate_id",
        "path_policy_id",
        "effective_path_policy_id",
        "requested_path_count",
        "selected_path_count",
        "fallback_path_count",
        "selected_path_ids",
        "fallback_path_ids",
        "fallback_policy_id",
        "path_downgrade_reason",
        "downgrade_reason",
        "coding_policy_id",
        "effective_coding_policy_id",
    ] {
        assert!(
            fields.contains(field),
            "structured log field must exist: {field}"
        );
    }
}

#[test]
fn transport_experiment_decision_emits_contract_metadata_fields() {
    use asupersync::transport::{
        AggregatorConfig, ExperimentalTransportGate, MultipathAggregator, PathCharacteristics,
        PathSelectionPolicy, TransportCodingPolicy, TransportExperimentContext, TransportPath,
    };

    let aggregator = MultipathAggregator::new(AggregatorConfig {
        path_policy: PathSelectionPolicy::BestQuality { count: 2 },
        experiment_gate: ExperimentalTransportGate::MultipathPreview,
        coding_policy: TransportCodingPolicy::RaptorQFecPreview,
        ..AggregatorConfig::default()
    });
    aggregator.paths().register(
        TransportPath::new(asupersync::transport::PathId(7), "wan-a", "10.0.0.1:9000")
            .with_characteristics(PathCharacteristics::high_quality()),
    );

    let decision = aggregator.experimental_transport_decision(TransportExperimentContext::new(
        "TW-MULTIPATH",
        "aa08-contract-smoke-001",
    ));
    let fields = decision.log_fields();

    for field in [
        "workload_id",
        "benchmark_correlation_id",
        "path_count",
        "experimental_gate_id",
        "path_policy_id",
        "effective_path_policy_id",
        "requested_path_count",
        "selected_path_count",
        "fallback_path_count",
        "selected_path_ids",
        "fallback_path_ids",
        "fallback_policy_id",
        "path_downgrade_reason",
        "downgrade_reason",
        "coding_policy_id",
        "effective_coding_policy_id",
    ] {
        assert!(
            fields.contains_key(field),
            "transport decision log field must exist: {field}"
        );
    }

    assert_eq!(
        fields.get("workload_id").map(String::as_str),
        Some("TW-MULTIPATH")
    );
    assert_eq!(
        fields.get("benchmark_correlation_id").map(String::as_str),
        Some("aa08-contract-smoke-001")
    );
    assert_eq!(fields.get("path_count").map(String::as_str), Some("1"));
    assert_eq!(
        fields.get("selected_path_ids").map(String::as_str),
        Some("7")
    );
    assert_eq!(
        fields.get("fallback_path_count").map(String::as_str),
        Some("0")
    );
    assert_eq!(
        fields.get("experimental_gate_id").map(String::as_str),
        Some("multipath-preview")
    );
    assert_eq!(
        fields.get("coding_policy_id").map(String::as_str),
        Some("raptorq-fec-preview")
    );
    assert_eq!(
        fields.get("effective_coding_policy_id").map(String::as_str),
        Some("disabled")
    );
}

// ── Smoke runner and scenarios ───────────────────────────────────────

#[test]
fn smoke_scenarios_are_rch_routed() {
    let artifact = load_artifact();
    let scenarios = artifact["smoke_scenarios"].as_array().expect("array");
    assert!(!scenarios.is_empty());
    for scenario in scenarios {
        let sid = scenario["scenario_id"].as_str().unwrap();
        let cmd = scenario["command"].as_str().unwrap();
        assert!(cmd.contains("rch exec --"), "scenario {sid} must use rch");
    }
}

#[test]
fn smoke_scenarios_include_validation_metadata() {
    let artifact = load_artifact();
    for scenario in artifact["smoke_scenarios"].as_array().expect("array") {
        let sid = scenario["scenario_id"].as_str().unwrap_or("<missing>");
        for field in [
            "scenario_id",
            "description",
            "workload_id",
            "validation_surface",
            "focus_dimension_ids",
            "command",
        ] {
            assert!(
                scenario.get(field).is_some(),
                "scenario {sid} missing field: {field}"
            );
        }
        assert!(
            scenario["focus_dimension_ids"].is_array(),
            "scenario {sid} focus_dimension_ids must be an array"
        );
    }
}

#[test]
fn smoke_scenarios_cover_fairness_handoff_overload_and_visibility_slices() {
    let artifact = load_artifact();
    let actual: BTreeSet<String> = artifact["smoke_scenarios"]
        .as_array()
        .expect("array")
        .iter()
        .map(|scenario| scenario["scenario_id"].as_str().unwrap().to_string())
        .collect();

    for required in [
        "AA08-SMOKE-FAIRNESS-FLOW-BALANCE",
        "AA08-SMOKE-HANDOFF-FALLBACK",
        "AA08-SMOKE-OVERLOAD-SIGNAL",
        "AA08-SMOKE-OPERATOR-VISIBILITY",
    ] {
        assert!(
            actual.contains(required),
            "missing smoke scenario {required}"
        );
    }
}

#[test]
fn fairness_smoke_scenario_points_to_round_robin_transport_replay() {
    let artifact = load_artifact();
    let fairness = artifact["smoke_scenarios"]
        .as_array()
        .expect("array")
        .iter()
        .find(|scenario| {
            scenario["scenario_id"].as_str() == Some("AA08-SMOKE-FAIRNESS-FLOW-BALANCE")
        })
        .expect("fairness smoke scenario must exist");

    assert_eq!(fairness["workload_id"].as_str(), Some("TW-FAIRNESS"));
    assert_eq!(
        fairness["validation_surface"].as_str(),
        Some("src/transport/tests.rs::test_transport_workload_tw_fairness_round_robin_balance")
    );
    assert_eq!(
        fairness["focus_dimension_ids"].as_array(),
        Some(&vec![
            Value::String("fairness".to_string()),
            Value::String("operator-visibility".to_string()),
        ])
    );
    assert!(
        fairness["command"]
            .as_str()
            .expect("command string")
            .contains("transport_workload_tw_fairness_round_robin_balance"),
        "fairness smoke command must target the deterministic transport workload test"
    );
}

#[test]
fn runner_script_exists_and_declares_modes() {
    let root = repo_root();
    let script_path = root.join(RUNNER_SCRIPT_PATH);
    assert!(script_path.exists());
    let script = std::fs::read_to_string(&script_path).unwrap();
    for token in [
        "--list",
        "--all",
        "--scenario",
        "--dry-run",
        "--execute",
        "transport-frontier-benchmark-smoke-bundle-v1",
        "transport-frontier-benchmark-smoke-run-report-v1",
        "transport-frontier-benchmark-smoke-suite-summary-v1",
        "AA08_RUN_ID",
        "AA08_TIMESTAMP",
        "AA08_FINISHED_AT",
        "AA08_OUTPUT_ROOT",
    ] {
        assert!(script.contains(token), "runner missing token: {token}");
    }
}

#[test]
fn runner_dry_run_emits_replay_metadata_bundle() {
    let root = repo_root();
    let output_root = tempfile::tempdir().expect("tempdir");
    let script_path = root.join(RUNNER_SCRIPT_PATH);

    let status = std::process::Command::new("bash")
        .arg(&script_path)
        .arg("--scenario")
        .arg("AA08-SMOKE-HANDOFF-FALLBACK")
        .arg("--dry-run")
        .current_dir(&root)
        .env("AA08_RUN_ID", "run_fixed")
        .env("AA08_TIMESTAMP", "2026-03-08T00:00:00Z")
        .env("AA08_OUTPUT_ROOT", output_root.path())
        .status()
        .expect("run dry-run script");
    assert!(status.success(), "dry-run script should succeed");

    let bundle_path = output_root
        .path()
        .join("run_fixed")
        .join("AA08-SMOKE-HANDOFF-FALLBACK")
        .join("bundle_manifest.json");
    let report_path = output_root
        .path()
        .join("run_fixed")
        .join("AA08-SMOKE-HANDOFF-FALLBACK")
        .join("run_report.json");
    assert!(bundle_path.exists(), "bundle manifest must be created");
    assert!(report_path.exists(), "dry-run report must be created");

    let raw = std::fs::read_to_string(&bundle_path).expect("read bundle manifest");
    let bundle: Value = serde_json::from_str(&raw).expect("parse bundle manifest");
    let report_raw = std::fs::read_to_string(&report_path).expect("read dry-run report");
    let report: Value = serde_json::from_str(&report_raw).expect("parse dry-run report");

    assert_eq!(
        bundle["schema"].as_str(),
        Some("transport-frontier-benchmark-smoke-bundle-v1")
    );
    assert_eq!(
        bundle["scenario_id"].as_str(),
        Some("AA08-SMOKE-HANDOFF-FALLBACK")
    );
    assert_eq!(bundle["workload_id"].as_str(), Some("TW-HANDOFF"));
    assert_eq!(
        bundle["validation_surface"].as_str(),
        Some(
            "src/transport/aggregator.rs::tests::test_path_set_primary_only_exposes_conservative_fallback"
        )
    );
    assert_eq!(
        bundle["runner_script"].as_str(),
        Some("scripts/run_transport_frontier_benchmark_smoke.sh")
    );
    assert_eq!(bundle["run_id"].as_str(), Some("run_fixed"));
    assert_eq!(bundle["timestamp"].as_str(), Some("2026-03-08T00:00:00Z"));
    assert_eq!(bundle["rch_routed"].as_bool(), Some(true));
    assert_eq!(
        bundle["bundle_manifest_path"].as_str(),
        bundle_path.to_str(),
        "bundle path should be recorded verbatim"
    );
    assert_eq!(
        report["schema"].as_str(),
        Some("transport-frontier-benchmark-smoke-run-report-v1")
    );
    assert_eq!(
        report["scenario_id"].as_str(),
        Some("AA08-SMOKE-HANDOFF-FALLBACK")
    );
    assert_eq!(report["mode"].as_str(), Some("dry-run"));
    assert_eq!(report["exit_code"].as_i64(), Some(0));
    assert_eq!(
        report["run_report_path"].as_str(),
        report_path.to_str(),
        "dry-run report path should be recorded verbatim"
    );
}

#[test]
fn runner_all_dry_run_emits_suite_summary() {
    let root = repo_root();
    let output_root = tempfile::tempdir().expect("tempdir");
    let script_path = root.join(RUNNER_SCRIPT_PATH);
    let artifact = load_artifact();

    let status = std::process::Command::new("bash")
        .arg(&script_path)
        .arg("--all")
        .arg("--dry-run")
        .current_dir(&root)
        .env("AA08_RUN_ID", "run_suite")
        .env("AA08_TIMESTAMP", "2026-03-08T00:00:00Z")
        .env("AA08_OUTPUT_ROOT", output_root.path())
        .status()
        .expect("run all dry-run script");
    assert!(status.success(), "all dry-run script should succeed");

    let summary_path = output_root.path().join("run_suite").join("summary.json");
    assert!(summary_path.exists(), "suite summary must be created");

    let raw = std::fs::read_to_string(&summary_path).expect("read suite summary");
    let summary: Value = serde_json::from_str(&raw).expect("parse suite summary");

    assert_eq!(
        summary["schema"].as_str(),
        Some("transport-frontier-benchmark-smoke-suite-summary-v1")
    );
    assert_eq!(summary["run_id"].as_str(), Some("run_suite"));
    assert_eq!(summary["mode"].as_str(), Some("dry-run"));
    assert_eq!(summary["status"].as_str(), Some("planned"));
    assert_eq!(summary["suite_exit_code"], Value::Null);
    assert_eq!(summary["all_rch_routed"].as_bool(), Some(true));
    assert_eq!(
        summary["summary_path"].as_str(),
        summary_path.to_str(),
        "summary path should be recorded verbatim"
    );

    let scenarios = summary["scenarios"]
        .as_array()
        .expect("scenarios must be array");
    let expected_count = artifact["smoke_scenarios"]
        .as_array()
        .expect("smoke_scenarios must be array")
        .len();
    assert_eq!(scenarios.len(), expected_count);
    assert_eq!(
        summary["scenario_count"].as_u64(),
        Some(expected_count as u64)
    );

    let expected_ids: Vec<&str> = artifact["smoke_scenarios"]
        .as_array()
        .unwrap()
        .iter()
        .map(|scenario| scenario["scenario_id"].as_str().unwrap())
        .collect();
    let actual_ids: Vec<&str> = summary["scenario_ids"]
        .as_array()
        .expect("scenario_ids must be array")
        .iter()
        .map(|id| id.as_str().expect("scenario id string"))
        .collect();
    assert_eq!(actual_ids, expected_ids);

    for scenario in scenarios {
        assert_eq!(scenario["status"].as_str(), Some("planned"));
        assert_eq!(scenario["exit_code"], Value::Null);
        let bundle_path = PathBuf::from(
            scenario["bundle_manifest_path"]
                .as_str()
                .expect("bundle path string"),
        );
        let report_path = PathBuf::from(
            scenario["run_report_path"]
                .as_str()
                .expect("report path string"),
        );
        assert!(bundle_path.exists(), "bundle manifest must exist");
        assert!(report_path.exists(), "dry-run report must exist");
    }
}

#[test]
fn runner_all_execute_emits_suite_summary_with_reports() {
    let root = repo_root();
    let output_root = tempfile::tempdir().expect("tempdir");
    let artifact_root = tempfile::tempdir().expect("artifact tempdir");
    let script_path = root.join(RUNNER_SCRIPT_PATH);
    let artifact_path = artifact_root
        .path()
        .join("transport_smoke_test_artifact.json");
    let custom_artifact = serde_json::json!({
        "contract_version": "transport-frontier-benchmark-v1",
        "smoke_scenarios": [
            {
                "scenario_id": "AA08-TEST-ONE",
                "description": "first execute scenario",
                "workload_id": "TW-MULTIPATH",
                "validation_surface": "tests::runner_all_execute_emits_suite_summary_with_reports",
                "focus_dimension_ids": ["operator-visibility"],
                "command": "printf 'scenario-one\\n'"
            },
            {
                "scenario_id": "AA08-TEST-TWO",
                "description": "second execute scenario",
                "workload_id": "TW-HANDOFF",
                "validation_surface": "tests::runner_all_execute_emits_suite_summary_with_reports",
                "focus_dimension_ids": ["failure-handling"],
                "command": "printf 'scenario-two\\n'"
            }
        ]
    });
    std::fs::write(
        &artifact_path,
        serde_json::to_string_pretty(&custom_artifact).expect("serialize custom artifact"),
    )
    .expect("write custom artifact");

    let status = std::process::Command::new("bash")
        .arg(&script_path)
        .arg("--all")
        .arg("--execute")
        .current_dir(&root)
        .env("AA08_ARTIFACT", &artifact_path)
        .env("AA08_RUN_ID", "run_execute")
        .env("AA08_TIMESTAMP", "2026-03-08T00:00:00Z")
        .env("AA08_FINISHED_AT", "2026-03-08T00:00:05Z")
        .env("AA08_OUTPUT_ROOT", output_root.path())
        .status()
        .expect("run all execute script");
    assert!(status.success(), "all execute script should succeed");

    let summary_path = output_root.path().join("run_execute").join("summary.json");
    assert!(summary_path.exists(), "suite summary must be created");

    let raw = std::fs::read_to_string(&summary_path).expect("read suite summary");
    let summary: Value = serde_json::from_str(&raw).expect("parse suite summary");

    assert_eq!(summary["mode"].as_str(), Some("execute"));
    assert_eq!(summary["status"].as_str(), Some("passed"));
    assert_eq!(summary["suite_exit_code"].as_i64(), Some(0));
    assert_eq!(summary["all_rch_routed"].as_bool(), Some(false));
    assert_eq!(summary["scenario_count"].as_u64(), Some(2));

    let scenarios = summary["scenarios"]
        .as_array()
        .expect("scenarios must be array");
    assert_eq!(scenarios.len(), 2);
    for scenario in scenarios {
        assert_eq!(scenario["status"].as_str(), Some("passed"));
        assert_eq!(scenario["exit_code"].as_i64(), Some(0));
        let report_path = PathBuf::from(
            scenario["run_report_path"]
                .as_str()
                .expect("report path string"),
        );
        let log_path = PathBuf::from(scenario["run_log_path"].as_str().expect("log path string"));
        assert!(report_path.exists(), "run report must exist");
        assert!(log_path.exists(), "run log must exist");
    }
}

#[test]
fn symbol_dispatcher_overload_rejected_deterministically() {
    use asupersync::security::authenticated::AuthenticatedSymbol;
    use asupersync::security::tag::AuthenticationTag;
    use asupersync::transport::{
        DispatchConfig, DispatchError, Endpoint, EndpointId, RouteKey, RoutingEntry, RoutingTable,
        SymbolDispatcher, SymbolRouter,
    };
    use asupersync::types::{Symbol, SymbolId, SymbolKind, Time};
    use std::sync::Arc;

    let table = Arc::new(RoutingTable::new());
    let endpoint = table.register_endpoint(Endpoint::new(EndpointId(1), "node-1:8080"));
    table.add_route(
        RouteKey::Default,
        RoutingEntry::new(vec![endpoint], Time::ZERO),
    );

    let router = Arc::new(SymbolRouter::new(table));
    let dispatcher = SymbolDispatcher::new(
        router,
        DispatchConfig {
            max_concurrent: 0,
            ..DispatchConfig::default()
        },
    );

    let symbol = AuthenticatedSymbol::new_verified(
        Symbol::new(SymbolId::new_for_test(1, 0, 1), vec![1], SymbolKind::Source),
        AuthenticationTag::zero(),
    );
    let cx = asupersync::Cx::for_testing();
    let result = futures_lite::future::block_on(dispatcher.dispatch(&cx, symbol));

    assert!(
        matches!(result, Err(DispatchError::Overloaded)),
        "dispatcher should reject immediately when max_concurrent=0: {result:?}"
    );
}

// ── Downstream beads ─────────────────────────────────────────────────

#[test]
fn downstream_beads_stay_in_aa_track_namespace() {
    let artifact = load_artifact();
    for bead in artifact["downstream_beads"].as_array().unwrap() {
        let bead = bead.as_str().unwrap();
        assert!(
            bead.starts_with("asupersync-1508v."),
            "must be AA namespace: {bead}"
        );
    }
}

// ── SimNetwork functional test ───────────────────────────────────────

#[cfg(feature = "test-internals")]
#[test]
fn sim_network_fully_connected_creates_paths() {
    use asupersync::transport::mock::{SimNetwork, SimTransportConfig};

    let config = SimTransportConfig::reliable();
    let net = SimNetwork::fully_connected(3, config);

    // Should be able to get transport between any pair
    let (sink, stream) = net.transport(0u64, 1u64);
    // Just verify they exist (no panic)
    drop(sink);
    drop(stream);
}

#[cfg(feature = "test-internals")]
#[test]
fn sim_network_ring_topology_creates_paths() {
    use asupersync::transport::mock::{SimNetwork, SimTransportConfig};

    let config = SimTransportConfig::reliable();
    let net = SimNetwork::ring(4, config);

    // Ring: node 0 connects to node 1
    let (sink, stream) = net.transport(0u64, 1u64);
    drop(sink);
    drop(stream);
}
