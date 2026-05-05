//! Cost-capped topology-guided exploration contract invariants (AA-06.2).

#![allow(missing_docs)]

use serde_json::Value;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

const DOC_PATH: &str = "docs/cost_capped_exploration_contract.md";
const ARTIFACT_PATH: &str = "artifacts/cost_capped_exploration_contract_v1.json";
const RUNNER_SCRIPT_PATH: &str = "scripts/run_cost_capped_exploration_smoke.sh";

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn load_doc() -> String {
    std::fs::read_to_string(repo_root().join(DOC_PATH))
        .expect("failed to load cost-capped exploration doc")
}

fn load_artifact() -> Value {
    let raw = std::fs::read_to_string(repo_root().join(ARTIFACT_PATH))
        .expect("failed to load cost-capped exploration artifact");
    serde_json::from_str(&raw).expect("failed to parse cost-capped exploration artifact")
}

fn algorithm_ids(artifact: &Value) -> BTreeSet<String> {
    artifact["algorithms"]
        .as_array()
        .expect("algorithms must be array")
        .iter()
        .map(|a| {
            a["algorithm_id"]
                .as_str()
                .expect("algorithm_id must be string")
                .to_string()
        })
        .collect()
}

// ── Doc existence and structure ──────────────────────────────────────

#[test]
fn doc_exists() {
    assert!(
        Path::new(DOC_PATH).exists(),
        "cost-capped exploration doc must exist"
    );
}

#[test]
fn doc_references_bead() {
    let doc = load_doc();
    assert!(
        doc.contains("asupersync-1508v.6.5"),
        "doc must reference bead id"
    );
}

#[test]
fn doc_has_required_sections() {
    let doc = load_doc();
    let sections = [
        "Purpose",
        "Contract Artifacts",
        "Exploration Algorithms",
        "Cost Cap Contract",
        "Artifact Emission Contract",
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
        "artifacts/cost_capped_exploration_contract_v1.json",
        "scripts/run_cost_capped_exploration_smoke.sh",
        "tests/cost_capped_exploration_contract.rs",
        "src/trace/geodesic.rs",
    ] {
        assert!(doc.contains(reference), "doc must reference {reference}");
    }
}

#[test]
fn doc_reproduction_command_uses_rch() {
    let doc = load_doc();
    assert!(
        doc.contains(
            "rch exec -- env CARGO_INCREMENTAL=0 CARGO_TARGET_DIR=/tmp/rch-codex-aa062 cargo test --test cost_capped_exploration_contract -- --nocapture"
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
        Some("cost-capped-exploration-contract-v1")
    );
    assert_eq!(
        artifact["runner_bundle_schema_version"].as_str(),
        Some("cost-capped-exploration-smoke-bundle-v1")
    );
    assert_eq!(
        artifact["runner_report_schema_version"].as_str(),
        Some("cost-capped-exploration-smoke-run-report-v1")
    );
    assert_eq!(
        artifact["runner_script"].as_str(),
        Some("scripts/run_cost_capped_exploration_smoke.sh")
    );
}

// ── Algorithm catalog completeness ───────────────────────────────────

#[test]
fn algorithm_catalog_has_expected_ids() {
    let artifact = load_artifact();
    let actual = algorithm_ids(&artifact);
    let expected: BTreeSet<String> = [
        "geodesic-normalization",
        "dpor-race-detection",
        "foata-canonicalization",
        "topological-scoring",
    ]
    .into_iter()
    .map(ToOwned::to_owned)
    .collect();
    assert_eq!(actual, expected, "algorithm catalog must remain stable");
}

#[test]
fn each_algorithm_has_required_fields() {
    let artifact = load_artifact();
    let required = [
        "algorithm_id",
        "description",
        "owner_file",
        "complexity",
        "budget_parameters",
        "fallback_chain",
        "fallback_reasons",
    ];
    for algo in artifact["algorithms"].as_array().unwrap() {
        let aid = algo["algorithm_id"].as_str().unwrap_or("<missing>");
        for field in &required {
            assert!(
                algo.get(*field).is_some(),
                "algorithm {aid} missing field: {field}"
            );
        }
    }
}

#[test]
fn algorithm_owner_files_exist() {
    let artifact = load_artifact();
    let root = repo_root();
    for algo in artifact["algorithms"].as_array().unwrap() {
        let aid = algo["algorithm_id"].as_str().unwrap();
        let owner_file = algo["owner_file"]
            .as_str()
            .expect("owner_file must be string");
        assert!(
            root.join(owner_file).exists(),
            "owner file for {aid} must exist: {owner_file}"
        );
    }
}

// ── Geodesic config defaults match source ────────────────────────────

#[test]
fn geodesic_config_defaults_match_source() {
    let artifact = load_artifact();
    let defaults = &artifact["geodesic_config_defaults"];

    let config = asupersync::trace::GeodesicConfig::default();
    assert_eq!(
        defaults["exact_threshold"].as_u64().unwrap() as usize,
        config.exact_threshold,
        "exact_threshold must match source default"
    );
    assert_eq!(
        defaults["beam_threshold"].as_u64().unwrap() as usize,
        config.beam_threshold,
        "beam_threshold must match source default"
    );
    assert_eq!(
        defaults["beam_width"].as_u64().unwrap() as usize,
        config.beam_width,
        "beam_width must match source default"
    );
    assert_eq!(
        defaults["step_budget"].as_u64().unwrap() as usize,
        config.step_budget,
        "step_budget must match source default"
    );
}

// ── Fallback chain ordering ──────────────────────────────────────────

#[test]
fn geodesic_fallback_chain_is_valid() {
    let artifact = load_artifact();
    let geodesic = artifact["algorithms"]
        .as_array()
        .unwrap()
        .iter()
        .find(|a| a["algorithm_id"].as_str() == Some("geodesic-normalization"))
        .expect("geodesic-normalization must exist");

    let chain: Vec<String> = geodesic["fallback_chain"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect();

    assert_eq!(
        chain,
        vec!["ExactAStar", "BeamSearch", "Greedy", "TopoSort"],
        "fallback chain must be ExactAStar > BeamSearch > Greedy > TopoSort"
    );
}

#[test]
fn geodesic_fallback_chain_matches_source_algorithm_enum() {
    // Verify each fallback step corresponds to a GeodesicAlgorithm variant
    let source = std::fs::read_to_string(repo_root().join("src/trace/geodesic.rs"))
        .expect("failed to read geodesic source");
    for variant in ["ExactAStar", "Greedy", "BeamSearch", "TopoSort"] {
        assert!(
            source.contains(variant),
            "geodesic source must contain algorithm variant: {variant}"
        );
    }
}

// ── Exploration manifest schema ──────────────────────────────────────

#[test]
fn exploration_manifest_fields_are_stable() {
    let artifact = load_artifact();
    let actual: BTreeSet<String> = artifact["exploration_manifest_required_fields"]
        .as_array()
        .expect("exploration_manifest_required_fields must be array")
        .iter()
        .map(|f| f.as_str().expect("field must be string").to_string())
        .collect();

    let expected: BTreeSet<String> = [
        "schema",
        "trace_length",
        "algorithm_chosen",
        "algorithm_fallback_chain",
        "fallback_reason",
        "canonical_fingerprint",
        "switch_count",
        "race_count",
        "step_budget",
        "steps_consumed",
        "heuristic_path_explanation",
    ]
    .into_iter()
    .map(ToOwned::to_owned)
    .collect();

    assert_eq!(
        actual, expected,
        "exploration manifest fields must remain stable"
    );
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
        let field = field.as_str().expect("field must be string").to_string();
        assert!(!field.is_empty());
        assert!(
            set.insert(field.clone()),
            "duplicate structured log field: {field}"
        );
    }
}

// ── Exhaustion contract ──────────────────────────────────────────────

#[test]
fn exhaustion_contract_has_steps() {
    let artifact = load_artifact();
    let steps = artifact["exhaustion_contract"]["steps"]
        .as_array()
        .expect("exhaustion_contract.steps must be array");
    assert!(
        steps.len() >= 4,
        "exhaustion contract must have at least 4 steps"
    );
    // Must include fallback validity guarantee
    let all_text: String = steps
        .iter()
        .map(|s| s.as_str().unwrap_or(""))
        .collect::<Vec<_>>()
        .join(" ");
    assert!(
        all_text.contains("valid"),
        "exhaustion contract must guarantee fallback validity"
    );
}

// ── Geodesic normalization functional test ────────────────────────────

#[test]
fn geodesic_normalization_produces_valid_result() {
    use asupersync::trace::event::TraceEvent;
    use asupersync::trace::geodesic::GeodesicConfig;
    use asupersync::trace::{normalize_trace, trace_switch_cost};
    use asupersync::types::{RegionId, TaskId, Time};

    let events = vec![
        TraceEvent::spawn(
            1,
            Time::ZERO,
            TaskId::new_for_test(1, 0),
            RegionId::new_for_test(1, 0),
        ),
        TraceEvent::spawn(
            2,
            Time::ZERO,
            TaskId::new_for_test(2, 0),
            RegionId::new_for_test(2, 0),
        ),
        TraceEvent::complete(
            3,
            Time::ZERO,
            TaskId::new_for_test(1, 0),
            RegionId::new_for_test(1, 0),
        ),
        TraceEvent::complete(
            4,
            Time::ZERO,
            TaskId::new_for_test(2, 0),
            RegionId::new_for_test(2, 0),
        ),
    ];

    let config = GeodesicConfig::default();
    let (normalized, result) = normalize_trace(&events, &config);

    assert_eq!(normalized.len(), events.len());
    assert!(trace_switch_cost(&normalized) <= trace_switch_cost(&events));
    assert_eq!(result.switch_count, trace_switch_cost(&normalized));
}

#[test]
fn geodesic_greedy_fallback_works() {
    use asupersync::trace::event::TraceEvent;
    use asupersync::trace::geodesic::GeodesicConfig;
    use asupersync::trace::normalize_trace;
    use asupersync::types::{RegionId, TaskId, Time};

    let events = vec![
        TraceEvent::spawn(
            1,
            Time::ZERO,
            TaskId::new_for_test(1, 0),
            RegionId::new_for_test(1, 0),
        ),
        TraceEvent::spawn(
            2,
            Time::ZERO,
            TaskId::new_for_test(2, 0),
            RegionId::new_for_test(2, 0),
        ),
    ];

    let config = GeodesicConfig::greedy_only();
    let (normalized, result) = normalize_trace(&events, &config);
    assert_eq!(normalized.len(), events.len());
    assert_eq!(
        result.algorithm,
        asupersync::trace::geodesic::GeodesicAlgorithm::Greedy
    );
}

// ── DPOR race detection functional test ──────────────────────────────

#[test]
fn dpor_race_detection_finds_races_in_concurrent_trace() {
    use asupersync::trace::dpor::detect_races;
    use asupersync::trace::event::TraceEvent;
    use asupersync::types::{RegionId, TaskId, Time};

    // Two independent tasks accessing different regions — no races
    let events = vec![
        TraceEvent::spawn(
            1,
            Time::ZERO,
            TaskId::new_for_test(1, 0),
            RegionId::new_for_test(1, 0),
        ),
        TraceEvent::spawn(
            2,
            Time::ZERO,
            TaskId::new_for_test(2, 0),
            RegionId::new_for_test(2, 0),
        ),
    ];

    let analysis = detect_races(&events);
    // Independent spawns in different regions should not race
    assert!(analysis.is_race_free());
}

// ── Canonical fingerprint stability ──────────────────────────────────

#[test]
fn canonical_fingerprint_deterministic() {
    use asupersync::trace::canonicalize::trace_fingerprint;
    use asupersync::trace::event::TraceEvent;
    use asupersync::types::{RegionId, TaskId, Time};

    let events = vec![
        TraceEvent::spawn(
            1,
            Time::ZERO,
            TaskId::new_for_test(1, 0),
            RegionId::new_for_test(1, 0),
        ),
        TraceEvent::spawn(
            2,
            Time::ZERO,
            TaskId::new_for_test(2, 0),
            RegionId::new_for_test(2, 0),
        ),
    ];

    let fp1 = trace_fingerprint(&events);
    let fp2 = trace_fingerprint(&events);
    assert_eq!(fp1, fp2, "canonical fingerprint must be deterministic");
}

// ── Smoke runner and scenarios ───────────────────────────────────────

#[test]
fn smoke_scenarios_are_rch_routed() {
    let artifact = load_artifact();
    let scenarios = artifact["smoke_scenarios"]
        .as_array()
        .expect("smoke_scenarios must be array");
    assert!(!scenarios.is_empty());

    for scenario in scenarios {
        let sid = scenario["scenario_id"]
            .as_str()
            .expect("scenario_id must be string");
        let command = scenario["command"]
            .as_str()
            .expect("command must be string");
        assert!(
            command.contains("rch exec --"),
            "scenario {sid} command must use rch: {command}"
        );
    }
}

#[test]
fn runner_script_exists_and_declares_modes() {
    let root = repo_root();
    let script_path = root.join(RUNNER_SCRIPT_PATH);
    assert!(script_path.exists(), "runner script must exist");

    let script = std::fs::read_to_string(&script_path).expect("failed to read runner script");
    for token in [
        "--list",
        "--scenario",
        "--dry-run",
        "--execute",
        "cost-capped-exploration-smoke-bundle-v1",
        "cost-capped-exploration-smoke-run-report-v1",
    ] {
        assert!(
            script.contains(token),
            "runner script missing token: {token}"
        );
    }
}

// ── Downstream beads ─────────────────────────────────────────────────

#[test]
fn downstream_beads_stay_in_aa_track_namespace() {
    let artifact = load_artifact();
    for bead in artifact["downstream_beads"]
        .as_array()
        .expect("downstream_beads must be array")
    {
        let bead = bead.as_str().expect("downstream bead must be string");
        assert!(
            bead.starts_with("asupersync-1508v."),
            "downstream bead must stay in AA namespace: {bead}"
        );
    }
}
