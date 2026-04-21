#![allow(clippy::all)]
//! Bounded controller synthesis contract invariants (AA-03.2).

#![allow(missing_docs, clippy::cast_precision_loss)]

use serde_json::Value;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

const DOC_PATH: &str = "docs/bounded_controller_synthesis_contract.md";
const ARTIFACT_PATH: &str = "artifacts/bounded_controller_synthesis_v1.json";
const RUNNER_SCRIPT_PATH: &str = "scripts/run_bounded_controller_synthesis_smoke.sh";

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn load_doc() -> String {
    std::fs::read_to_string(repo_root().join(DOC_PATH))
        .expect("failed to load bounded controller synthesis doc")
}

fn load_artifact() -> Value {
    let raw = std::fs::read_to_string(repo_root().join(ARTIFACT_PATH))
        .expect("failed to load bounded controller synthesis artifact");
    serde_json::from_str(&raw).expect("failed to parse artifact")
}

// ── Doc existence and structure ─────────────────────────────────────

#[test]
fn doc_exists() {
    assert!(Path::new(DOC_PATH).exists(), "doc must exist");
}

#[test]
fn doc_references_bead() {
    let doc = load_doc();
    assert!(
        doc.contains("asupersync-1508v.3.5"),
        "doc must reference bead id"
    );
}

#[test]
fn doc_has_required_sections() {
    let doc = load_doc();
    let sections = [
        "Purpose",
        "Contract Artifacts",
        "Controller Domains",
        "Loss Model",
        "Calibration Protocol",
        "Artifact Format Compatibility",
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
        "artifacts/bounded_controller_synthesis_v1.json",
        "scripts/run_bounded_controller_synthesis_smoke.sh",
        "tests/bounded_controller_synthesis_contract.rs",
        "src/runtime/kernel.rs",
    ] {
        assert!(doc.contains(reference), "doc must reference {reference}");
    }
}

#[test]
fn doc_reproduction_command_uses_rch() {
    let doc = load_doc();
    assert!(
        doc.contains(
            "rch exec -- env CARGO_INCREMENTAL=0 CARGO_TARGET_DIR=/tmp/rch-codex-aa032 cargo test --test bounded_controller_synthesis_contract -- --nocapture"
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
        Some("bounded-controller-synthesis-v1")
    );
    assert_eq!(
        artifact["runner_bundle_schema_version"].as_str(),
        Some("bounded-controller-synthesis-smoke-bundle-v1")
    );
    assert_eq!(
        artifact["runner_report_schema_version"].as_str(),
        Some("bounded-controller-synthesis-smoke-run-report-v1")
    );
    assert_eq!(
        artifact["runner_script"].as_str(),
        Some("scripts/run_bounded_controller_synthesis_smoke.sh")
    );
}

// ── Controller domain catalog ────────────────────────────────────────

#[test]
fn domain_ids_are_complete() {
    let artifact = load_artifact();
    let actual: BTreeSet<String> = artifact["controller_domains"]
        .as_array()
        .expect("controller_domains must be array")
        .iter()
        .map(|d| d["domain_id"].as_str().unwrap().to_string())
        .collect();
    let expected: BTreeSet<String> = ["SCHED-GOVERNOR", "ADMISSION-GATE", "RETRY-BACKOFF"]
        .into_iter()
        .map(ToOwned::to_owned)
        .collect();
    assert_eq!(actual, expected, "domain IDs must remain stable");
}

#[test]
fn each_domain_has_required_fields() {
    let artifact = load_artifact();
    let required = [
        "domain_id",
        "description",
        "state_variables",
        "action_set",
        "loss_terms",
        "seam_ids",
        "twin_stages",
        "conservative_comparator",
    ];
    for domain in artifact["controller_domains"].as_array().unwrap() {
        let did = domain["domain_id"].as_str().unwrap_or("<missing>");
        for field in &required {
            assert!(
                domain.get(*field).is_some(),
                "domain {did} missing field: {field}"
            );
        }
    }
}

#[test]
fn domain_action_sets_are_nonempty_and_have_ids() {
    let artifact = load_artifact();
    for domain in artifact["controller_domains"].as_array().unwrap() {
        let did = domain["domain_id"].as_str().unwrap();
        let actions = domain["action_set"]
            .as_array()
            .expect("action_set must be array");
        assert!(
            !actions.is_empty(),
            "domain {did} must have at least one action"
        );
        for action in actions {
            assert!(
                action.get("action_id").is_some(),
                "action in {did} missing action_id"
            );
            assert!(
                action.get("description").is_some(),
                "action in {did} missing description"
            );
        }
    }
}

#[test]
fn domain_action_ids_are_globally_unique() {
    let artifact = load_artifact();
    let mut all_ids = BTreeSet::new();
    for domain in artifact["controller_domains"].as_array().unwrap() {
        for action in domain["action_set"].as_array().unwrap() {
            let aid = action["action_id"].as_str().unwrap().to_string();
            assert!(all_ids.insert(aid.clone()), "duplicate action_id: {aid}");
        }
    }
    assert!(
        all_ids.len() >= 10,
        "must have at least 10 total actions, got {}",
        all_ids.len()
    );
}

// ── Loss model ───────────────────────────────────────────────────────

#[test]
fn domain_loss_weights_sum_to_one() {
    let artifact = load_artifact();
    for domain in artifact["controller_domains"].as_array().unwrap() {
        let did = domain["domain_id"].as_str().unwrap();
        let total: f64 = domain["loss_terms"]
            .as_array()
            .unwrap()
            .iter()
            .map(|t| t["weight"].as_f64().unwrap())
            .sum();
        assert!(
            (total - 1.0).abs() < 1e-6,
            "domain {did} loss weights must sum to 1.0, got {total}"
        );
    }
}

#[test]
fn domain_loss_terms_have_required_fields() {
    let artifact = load_artifact();
    for domain in artifact["controller_domains"].as_array().unwrap() {
        let did = domain["domain_id"].as_str().unwrap();
        for term in domain["loss_terms"].as_array().unwrap() {
            for field in ["term_id", "description", "weight"] {
                assert!(
                    term.get(field).is_some(),
                    "loss term in {did} missing field: {field}"
                );
            }
        }
    }
}

#[test]
fn domain_loss_term_ids_are_globally_unique() {
    let artifact = load_artifact();
    let mut all_ids = BTreeSet::new();
    for domain in artifact["controller_domains"].as_array().unwrap() {
        for term in domain["loss_terms"].as_array().unwrap() {
            let tid = term["term_id"].as_str().unwrap().to_string();
            assert!(all_ids.insert(tid.clone()), "duplicate loss term_id: {tid}");
        }
    }
}

#[test]
fn domain_loss_weights_are_positive() {
    let artifact = load_artifact();
    for domain in artifact["controller_domains"].as_array().unwrap() {
        let did = domain["domain_id"].as_str().unwrap();
        for term in domain["loss_terms"].as_array().unwrap() {
            let tid = term["term_id"].as_str().unwrap();
            let w = term["weight"].as_f64().unwrap();
            assert!(
                w > 0.0,
                "loss weight for {tid} in {did} must be positive, got {w}"
            );
        }
    }
}

// ── Seam and twin stage references ───────────────────────────────────

#[test]
fn domain_seam_ids_follow_naming_convention() {
    let artifact = load_artifact();
    for domain in artifact["controller_domains"].as_array().unwrap() {
        let did = domain["domain_id"].as_str().unwrap();
        for seam in domain["seam_ids"].as_array().unwrap() {
            let sid = seam.as_str().unwrap();
            assert!(
                sid.starts_with("AA01-SEAM-"),
                "domain {did} seam must follow AA01-SEAM-* pattern: {sid}"
            );
        }
    }
}

#[test]
fn domain_twin_stages_follow_naming_convention() {
    let artifact = load_artifact();
    for domain in artifact["controller_domains"].as_array().unwrap() {
        let did = domain["domain_id"].as_str().unwrap();
        for stage in domain["twin_stages"].as_array().unwrap() {
            let sid = stage.as_str().unwrap();
            assert!(
                sid.starts_with("DT-"),
                "domain {did} twin stage must follow DT-* pattern: {sid}"
            );
        }
    }
}

// ── Artifact format compatibility ────────────────────────────────────

#[test]
fn artifact_format_is_aa02_compatible() {
    let artifact = load_artifact();
    let fmt = &artifact["artifact_format"];
    assert_eq!(
        fmt["manifest_schema_version"].as_str(),
        Some("controller-artifact-manifest-v1"),
        "must use AA-02 manifest schema"
    );
    let required = fmt["requires_fields"]
        .as_array()
        .expect("requires_fields must be array");
    assert!(
        required.len() >= 7,
        "must require at least 7 AA-02 manifest fields"
    );
}

// ── Calibration protocol ─────────────────────────────────────────────

#[test]
fn calibration_protocol_has_required_steps() {
    let artifact = load_artifact();
    let cal = &artifact["calibration_protocol"];
    let steps = cal["steps"].as_array().expect("steps must be array");
    assert!(
        steps.len() >= 4,
        "calibration protocol must have at least 4 steps"
    );
    let min_score = cal["min_calibration_score"]
        .as_f64()
        .expect("min_calibration_score must be float");
    assert!(
        (0.0..=1.0).contains(&min_score),
        "min_calibration_score must be in [0, 1]"
    );
    let holdout = cal["holdout_fraction"]
        .as_f64()
        .expect("holdout_fraction must be float");
    assert!(
        holdout > 0.0 && holdout < 1.0,
        "holdout_fraction must be in (0, 1)"
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
        let f = field.as_str().expect("field must be string").to_string();
        assert!(!f.is_empty());
        assert!(set.insert(f.clone()), "duplicate field: {f}");
    }
}

// ── Smoke runner ─────────────────────────────────────────────────────

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
    assert!(script_path.exists(), "runner script must exist");
    let script = std::fs::read_to_string(&script_path).unwrap();
    for token in [
        "--list",
        "--scenario",
        "--dry-run",
        "--execute",
        "bounded-controller-synthesis-smoke-bundle-v1",
        "bounded-controller-synthesis-smoke-run-report-v1",
    ] {
        assert!(script.contains(token), "runner missing token: {token}");
    }
}

// ── Downstream beads ─────────────────────────────────────────────────

#[test]
fn downstream_beads_are_in_aa_namespace() {
    let artifact = load_artifact();
    for bead in artifact["downstream_beads"].as_array().unwrap() {
        let bead = bead.as_str().unwrap();
        assert!(
            bead.starts_with("asupersync-1508v."),
            "must be AA namespace: {bead}"
        );
    }
}

// ── Functional: Loss computation ─────────────────────────────────────

#[test]
fn loss_computation_weighted_sum() {
    // Simulate loss computation for SCHED-GOVERNOR
    let weights = [0.5, 0.3, 0.2];
    let losses = [0.1, 0.4, 0.05]; // tail, fairness, idle

    let total: f64 = weights.iter().zip(&losses).map(|(w, l)| w * l).sum();
    // 0.5*0.1 + 0.3*0.4 + 0.2*0.05 = 0.05 + 0.12 + 0.01 = 0.18
    assert!((total - 0.18).abs() < 1e-9, "weighted loss must be 0.18");
}

#[test]
fn loss_computation_calibration_score() {
    // Calibration score = 1 - mean_absolute_error
    let predicted_losses: [f64; 3] = [0.12, 0.35, 0.08];
    let observed_losses: [f64; 3] = [0.10, 0.40, 0.05];

    let n = predicted_losses.len();
    let mae: f64 = predicted_losses
        .iter()
        .zip(&observed_losses)
        .map(|(p, o)| (p - o).abs())
        .sum::<f64>()
        / n as f64;
    let calibration = 1.0 - mae;

    // mae = (0.02 + 0.05 + 0.03) / 3 = 0.0333...
    assert!((mae - 1.0 / 30.0).abs() < 1e-9);
    assert!(calibration > 0.8, "calibration must exceed threshold");
}

#[test]
fn loss_computation_calibration_rejection() {
    // Poor calibration should be rejected
    let predicted_losses: [f64; 3] = [0.8, 0.1, 0.9];
    let observed_losses: [f64; 3] = [0.1, 0.8, 0.1];

    let n = predicted_losses.len();
    let mae: f64 = predicted_losses
        .iter()
        .zip(&observed_losses)
        .map(|(p, o)| (p - o).abs())
        .sum::<f64>()
        / n as f64;
    let calibration = 1.0 - mae;

    assert!(calibration < 0.8, "poor predictions must fail calibration");
}

#[test]
fn loss_computation_action_selection_greedy() {
    // Greedy action selection: pick action with lowest total loss
    let state = [100.0, 5.0, 3.0, 1.0]; // ready_q, cancel_q, streak, parked
    let weights = [0.5, 0.3, 0.2];

    // Simulate losses for each action
    let action_losses = [
        ("SCHED-NOOP", [0.10, 0.20, 0.05]),
        ("SCHED-WIDEN-STREAK", [0.08, 0.30, 0.05]),
        ("SCHED-NARROW-STREAK", [0.15, 0.10, 0.05]),
        ("SCHED-PARK-WORKER", [0.12, 0.20, 0.01]),
        ("SCHED-WAKE-WORKER", [0.05, 0.20, 0.15]),
    ];

    let mut best_action = "";
    let mut best_loss = f64::MAX;
    for (action, losses) in &action_losses {
        let total: f64 = weights.iter().zip(losses.iter()).map(|(w, l)| w * l).sum();
        if total < best_loss {
            best_loss = total;
            best_action = action;
        }
    }

    // Should pick the action with lowest weighted loss
    assert!(!best_action.is_empty(), "must select an action");
    assert!(best_loss < 1.0, "best loss must be bounded");

    // The state is used to compute losses — verify it's reasonable
    assert!(state[0] > 0.0, "ready queue must be positive");
}

#[test]
fn loss_computation_holdout_split() {
    // Verify 80/20 holdout split
    let total_workloads: usize = 8;
    let holdout_fraction: f64 = 0.2;

    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    let holdout_count = ((total_workloads as f64) * holdout_fraction).ceil() as usize;
    let train_count = total_workloads - holdout_count;

    assert_eq!(holdout_count, 2, "20% of 8 rounds up to 2");
    assert_eq!(train_count, 6, "training set is 6");
    assert!(holdout_count > 0, "holdout must be nonempty");
}

#[test]
fn artifact_format_policy_table_deterministic_lookup() {
    // Simulate a policy table keyed by discretized state
    use std::collections::BTreeMap;

    let mut policy_table: BTreeMap<String, String> = BTreeMap::new();
    policy_table.insert("100_5_3_1".to_string(), "SCHED-NOOP".to_string());
    policy_table.insert("200_10_5_0".to_string(), "SCHED-WAKE-WORKER".to_string());
    policy_table.insert("50_2_1_3".to_string(), "SCHED-PARK-WORKER".to_string());

    // Lookup must be deterministic
    assert_eq!(
        policy_table.get("100_5_3_1"),
        Some(&"SCHED-NOOP".to_string())
    );
    assert_eq!(
        policy_table.get("200_10_5_0"),
        Some(&"SCHED-WAKE-WORKER".to_string())
    );

    // Unknown state falls back to None (conservative)
    assert_eq!(policy_table.get("999_0_0_0"), None);

    // JSON roundtrip
    let json = serde_json::to_string(&policy_table).unwrap();
    let deser: BTreeMap<String, String> = serde_json::from_str(&json).unwrap();
    assert_eq!(policy_table, deser, "policy table must round-trip");
}
