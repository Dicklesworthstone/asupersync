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
    assert!(doc.contains("asupersync-1508v.8.4"), "doc must reference bead id");
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
        missing.iter().map(|s| format!("  - {s}")).collect::<Vec<_>>().join("\n")
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
            assert!(root.join(path).exists(), "owner file for {cid} must exist: {path}");
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
            assert!(workload.get(field).is_some(), "workload {wid} missing field: {field}");
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
        for field in ["experiment_id", "description", "hypothesis", "key_dimensions"] {
            assert!(experiment.get(field).is_some(), "experiment {eid} missing field: {field}");
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
fn runner_script_exists_and_declares_modes() {
    let root = repo_root();
    let script_path = root.join(RUNNER_SCRIPT_PATH);
    assert!(script_path.exists());
    let script = std::fs::read_to_string(&script_path).unwrap();
    for token in [
        "--list", "--scenario", "--dry-run", "--execute",
        "transport-frontier-benchmark-smoke-bundle-v1",
        "transport-frontier-benchmark-smoke-run-report-v1",
    ] {
        assert!(script.contains(token), "runner missing token: {token}");
    }
}

// ── Downstream beads ─────────────────────────────────────────────────

#[test]
fn downstream_beads_stay_in_aa_track_namespace() {
    let artifact = load_artifact();
    for bead in artifact["downstream_beads"].as_array().unwrap() {
        let bead = bead.as_str().unwrap();
        assert!(bead.starts_with("asupersync-1508v."), "must be AA namespace: {bead}");
    }
}

// ── SimNetwork functional test ───────────────────────────────────────

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
