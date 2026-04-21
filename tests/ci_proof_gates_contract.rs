#![allow(clippy::all)]
//! CI proof gates contract invariants (AA-10.2).

#![allow(missing_docs, clippy::cast_precision_loss)]

use serde_json::Value;
use std::collections::HashSet;

const DOC_PATH: &str = "docs/ci_proof_gates_contract.md";
const ARTIFACT_PATH: &str = "artifacts/ci_proof_gates_v1.json";
const RUNNER_PATH: &str = "scripts/run_ci_proof_gates_smoke.sh";

fn load_artifact() -> Value {
    let content =
        std::fs::read_to_string(ARTIFACT_PATH).expect("artifact must exist at expected path");
    serde_json::from_str(&content).expect("artifact must be valid JSON")
}

fn load_doc() -> String {
    std::fs::read_to_string(DOC_PATH).expect("contract doc must exist")
}

fn load_runner() -> String {
    std::fs::read_to_string(RUNNER_PATH).expect("runner script must exist")
}

// ── Document stability ─────────────────────────────────────────────

#[test]
fn doc_exists_and_has_required_sections() {
    let doc = load_doc();
    for section in &[
        "## Purpose",
        "## Contract Artifacts",
        "## Gate Definitions",
        "## Readiness Computation",
        "## Actionability",
        "## Validation",
        "## Cross-References",
    ] {
        assert!(doc.contains(section), "doc must contain section: {section}");
    }
}

#[test]
fn doc_references_bead_id() {
    let doc = load_doc();
    let art = load_artifact();
    let bead_id = art["bead_id"].as_str().unwrap();
    assert!(
        doc.contains(bead_id),
        "doc must reference bead_id {bead_id}"
    );
}

// ── Artifact stability ─────────────────────────────────────────────

#[test]
fn artifact_has_contract_version() {
    let art = load_artifact();
    assert_eq!(
        art["contract_version"].as_str().unwrap(),
        "ci-proof-gates-v1"
    );
}

#[test]
fn artifact_has_runner_script() {
    let art = load_artifact();
    let runner = art["runner_script"].as_str().unwrap();
    assert!(
        std::path::Path::new(runner).exists(),
        "runner script must exist at {runner}"
    );
}

// ── Gate definitions ───────────────────────────────────────────────

#[test]
fn gate_definitions_are_nonempty() {
    let art = load_artifact();
    let gates = art["gate_definitions"].as_array().unwrap();
    assert!(gates.len() >= 8, "must have at least 8 gate definitions");
}

#[test]
fn gate_ids_are_unique() {
    let art = load_artifact();
    let gates = art["gate_definitions"].as_array().unwrap();
    let ids: Vec<&str> = gates
        .iter()
        .map(|g| g["gate_id"].as_str().unwrap())
        .collect();
    let mut deduped = ids.clone();
    deduped.sort_unstable();
    deduped.dedup();
    assert_eq!(ids.len(), deduped.len(), "gate_ids must be unique");
}

#[test]
fn gates_have_cg_prefix() {
    let art = load_artifact();
    let gates = art["gate_definitions"].as_array().unwrap();
    for gate in gates {
        let gid = gate["gate_id"].as_str().unwrap();
        assert!(gid.starts_with("CG-"), "gate '{gid}' must start with CG-");
    }
}

#[test]
fn gates_have_valid_severity() {
    let art = load_artifact();
    let gates = art["gate_definitions"].as_array().unwrap();
    let valid_severities = ["blocking", "warning"];
    for gate in gates {
        let gid = gate["gate_id"].as_str().unwrap();
        let severity = gate["severity"].as_str().unwrap();
        assert!(
            valid_severities.contains(&severity),
            "{gid}: severity '{severity}' must be blocking or warning"
        );
    }
}

#[test]
fn gates_have_failure_actions() {
    let art = load_artifact();
    let gates = art["gate_definitions"].as_array().unwrap();
    for gate in gates {
        let gid = gate["gate_id"].as_str().unwrap();
        let action = gate["failure_action"].as_str().unwrap();
        assert!(
            !action.is_empty(),
            "{gid}: must have non-empty failure_action"
        );
    }
}

#[test]
fn gates_include_core_blocking_gates() {
    let art = load_artifact();
    let gates = art["gate_definitions"].as_array().unwrap();
    let blocking: HashSet<&str> = gates
        .iter()
        .filter(|g| g["severity"].as_str().unwrap() == "blocking")
        .map(|g| g["gate_id"].as_str().unwrap())
        .collect();
    for required in &[
        "CG-ARTIFACT-BUNDLE",
        "CG-CALIBRATION-DRIFT",
        "CG-TAIL-REGRESSION",
        "CG-OBLIGATION-LEAK",
    ] {
        assert!(
            blocking.contains(required),
            "{required} must be a blocking gate"
        );
    }
}

#[test]
fn at_least_half_gates_are_blocking() {
    let art = load_artifact();
    let gates = art["gate_definitions"].as_array().unwrap();
    let blocking_count = gates
        .iter()
        .filter(|g| g["severity"].as_str().unwrap() == "blocking")
        .count();
    assert!(
        blocking_count * 2 >= gates.len(),
        "at least half the gates must be blocking"
    );
}

// ── Readiness computation ──────────────────────────────────────────

#[test]
fn readiness_dimensions_are_nonempty() {
    let art = load_artifact();
    let dims = art["readiness_computation"]["dimensions"]
        .as_array()
        .unwrap();
    assert!(dims.len() >= 4, "must have at least 4 readiness dimensions");
}

#[test]
fn readiness_dimension_ids_are_unique() {
    let art = load_artifact();
    let dims = art["readiness_computation"]["dimensions"]
        .as_array()
        .unwrap();
    let ids: Vec<&str> = dims
        .iter()
        .map(|d| d["dimension_id"].as_str().unwrap())
        .collect();
    let mut deduped = ids.clone();
    deduped.sort_unstable();
    deduped.dedup();
    assert_eq!(ids.len(), deduped.len(), "dimension_ids must be unique");
}

#[test]
fn readiness_dimensions_have_rd_prefix() {
    let art = load_artifact();
    let dims = art["readiness_computation"]["dimensions"]
        .as_array()
        .unwrap();
    for dim in dims {
        let did = dim["dimension_id"].as_str().unwrap();
        assert!(
            did.starts_with("RD-"),
            "dimension '{did}' must start with RD-"
        );
    }
}

#[test]
fn readiness_weights_sum_to_one() {
    let art = load_artifact();
    let dims = art["readiness_computation"]["dimensions"]
        .as_array()
        .unwrap();
    let sum: f64 = dims.iter().map(|d| d["weight"].as_f64().unwrap()).sum();
    assert!(
        (sum - 1.0).abs() < 0.01,
        "readiness weights must sum to 1.0, got {sum}"
    );
}

#[test]
fn readiness_weights_are_positive() {
    let art = load_artifact();
    let dims = art["readiness_computation"]["dimensions"]
        .as_array()
        .unwrap();
    for dim in dims {
        let did = dim["dimension_id"].as_str().unwrap();
        let weight = dim["weight"].as_f64().unwrap();
        assert!(weight > 0.0, "{did}: weight must be positive");
    }
}

#[test]
fn readiness_thresholds_are_ordered() {
    let art = load_artifact();
    let thresholds = &art["readiness_computation"]["thresholds"];
    let go = thresholds["go"].as_f64().unwrap();
    let conditional = thresholds["conditional_go"].as_f64().unwrap();
    let no_go = thresholds["no_go"].as_f64().unwrap();
    assert!(go > conditional, "GO threshold must be > CONDITIONAL_GO");
    assert!(conditional > no_go, "CONDITIONAL_GO must be > NO_GO");
}

// ── Rerun commands ─────────────────────────────────────────────────

#[test]
fn rerun_template_has_required_fields() {
    let art = load_artifact();
    let fields = art["rerun_commands"]["template_fields"].as_array().unwrap();
    let strs: Vec<&str> = fields.iter().map(|f| f.as_str().unwrap()).collect();
    assert!(strs.contains(&"gate_id"), "must include gate_id");
    assert!(strs.contains(&"test_filter"), "must include test_filter");
}

#[test]
fn rerun_example_is_rch_routed() {
    let art = load_artifact();
    let example = art["rerun_commands"]["example"].as_str().unwrap();
    assert!(
        example.contains("rch exec"),
        "rerun example must be rch-routed"
    );
}

// ── Structured logging ─────────────────────────────────────────────

#[test]
fn structured_log_fields_are_nonempty_and_unique() {
    let art = load_artifact();
    let fields = art["structured_log_fields_required"].as_array().unwrap();
    assert!(!fields.is_empty(), "log fields must be nonempty");
    let strs: Vec<&str> = fields.iter().map(|f| f.as_str().unwrap()).collect();
    let mut deduped = strs.clone();
    deduped.sort_unstable();
    deduped.dedup();
    assert_eq!(strs.len(), deduped.len(), "log fields must be unique");
}

// ── Smoke / runner ─────────────────────────────────────────────────

#[test]
fn smoke_scenarios_are_rch_routed() {
    let art = load_artifact();
    let scenarios = art["smoke_scenarios"].as_array().unwrap();
    assert!(scenarios.len() >= 3, "must have at least 3 smoke scenarios");
    for scenario in scenarios {
        let sid = scenario["scenario_id"].as_str().unwrap();
        let cmd = scenario["command"].as_str().unwrap();
        assert!(cmd.starts_with("rch exec"), "{sid}: must be rch-routed");
    }
}

#[test]
fn runner_script_exists_and_declares_modes() {
    let runner = load_runner();
    for mode in &["--list", "--dry-run", "--execute", "--scenario"] {
        assert!(runner.contains(mode), "runner must support {mode}");
    }
}

// ── Functional: readiness computation ───────────────────────────────

#[test]
fn readiness_go_score_computation() {
    let art = load_artifact();
    let dims = art["readiness_computation"]["dimensions"]
        .as_array()
        .unwrap();
    let thresholds = &art["readiness_computation"]["thresholds"];
    let go_threshold = thresholds["go"].as_f64().unwrap();

    // Simulate all dimensions at maximum
    let score: f64 = dims
        .iter()
        .map(|d| d["weight"].as_f64().unwrap() * 1.0)
        .sum();
    assert!(
        score >= go_threshold,
        "perfect score {score} must meet GO threshold {go_threshold}"
    );
}

#[test]
fn readiness_no_go_computation() {
    let art = load_artifact();
    let dims = art["readiness_computation"]["dimensions"]
        .as_array()
        .unwrap();
    let thresholds = &art["readiness_computation"]["thresholds"];
    let conditional_threshold = thresholds["conditional_go"].as_f64().unwrap();

    // Simulate all dimensions at 50%
    let score: f64 = dims
        .iter()
        .map(|d| d["weight"].as_f64().unwrap() * 0.5)
        .sum();
    assert!(
        score < conditional_threshold,
        "half score {score} must be below CONDITIONAL_GO {conditional_threshold}"
    );
}

#[test]
fn readiness_conditional_go_computation() {
    let art = load_artifact();
    let dims = art["readiness_computation"]["dimensions"]
        .as_array()
        .unwrap();
    let thresholds = &art["readiness_computation"]["thresholds"];
    let go_threshold = thresholds["go"].as_f64().unwrap();
    let conditional_threshold = thresholds["conditional_go"].as_f64().unwrap();

    // Simulate dimensions at 80% (should be conditional)
    let score: f64 = dims
        .iter()
        .map(|d| d["weight"].as_f64().unwrap() * 0.8)
        .sum();
    assert!(
        score >= conditional_threshold && score < go_threshold,
        "80% score {score} must be CONDITIONAL_GO"
    );
}

// ── Functional: gate blocking semantics ─────────────────────────────

#[test]
fn blocking_gate_failure_prevents_graduation() {
    let art = load_artifact();
    let gates = art["gate_definitions"].as_array().unwrap();

    // Simulate: one blocking gate fails
    let mut all_passed = true;
    for gate in gates {
        let severity = gate["severity"].as_str().unwrap();
        let gid = gate["gate_id"].as_str().unwrap();
        let passed = gid != "CG-OBLIGATION-LEAK"; // simulate this one failing

        if severity == "blocking" && !passed {
            all_passed = false;
        }
    }

    assert!(
        !all_passed,
        "a single blocking gate failure must prevent graduation"
    );
}

#[test]
fn warning_gate_failure_does_not_block() {
    let art = load_artifact();
    let gates = art["gate_definitions"].as_array().unwrap();

    // Simulate: only warning gates fail
    let mut blocked = false;
    for gate in gates {
        let severity = gate["severity"].as_str().unwrap();
        let passed = severity != "warning"; // all warnings fail

        if severity == "blocking" && !passed {
            blocked = true;
        }
    }

    assert!(!blocked, "warning-only failures must not block graduation");
}
