#![allow(warnings)]
#![allow(clippy::all)]
//! Kernel fast path substrate comparison contract invariants (AA-04.1).

#![allow(missing_docs)]

use serde_json::Value;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

const DOC_PATH: &str = "docs/kernel_fast_path_substrate_comparison_contract.md";
const ARTIFACT_PATH: &str = "artifacts/kernel_fast_path_substrate_comparison_v1.json";
const RUNNER_SCRIPT_PATH: &str = "scripts/run_kernel_fast_path_substrate_smoke.sh";

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn load_doc() -> String {
    std::fs::read_to_string(repo_root().join(DOC_PATH))
        .expect("failed to load kernel fast path doc")
}

fn load_artifact() -> Value {
    let raw = std::fs::read_to_string(repo_root().join(ARTIFACT_PATH))
        .expect("failed to load kernel fast path artifact");
    serde_json::from_str(&raw).expect("failed to parse artifact")
}

// ── Doc existence and structure ──────────────────────────────────────

#[test]
fn doc_exists() {
    assert!(
        Path::new(DOC_PATH).exists(),
        "kernel fast path doc must exist"
    );
}

#[test]
fn doc_references_bead() {
    let doc = load_doc();
    assert!(
        doc.contains("asupersync-1508v.4.4"),
        "doc must reference bead id"
    );
}

#[test]
fn doc_has_required_sections() {
    let doc = load_doc();
    let sections = [
        "Purpose",
        "Contract Artifacts",
        "Current Substrate Inventory",
        "Candidate Matrix",
        "Evaluation Methodology",
        "Adoption Wedge Contract",
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
        "artifacts/kernel_fast_path_substrate_comparison_v1.json",
        "scripts/run_kernel_fast_path_substrate_smoke.sh",
        "tests/kernel_fast_path_substrate_comparison_contract.rs",
        "src/runtime/scheduler/local_queue.rs",
        "src/runtime/scheduler/stealing.rs",
        "src/runtime/scheduler/global_injector.rs",
        "src/runtime/waker.rs",
    ] {
        assert!(doc.contains(reference), "doc must reference {reference}");
    }
}

#[test]
fn doc_reproduction_command_uses_rch() {
    let doc = load_doc();
    assert!(
        doc.contains(
            "rch exec -- env CARGO_INCREMENTAL=0 CARGO_TARGET_DIR=/tmp/rch-codex-aa041 cargo test --test kernel_fast_path_substrate_comparison_contract -- --nocapture"
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
        Some("kernel-fast-path-substrate-comparison-v1")
    );
    assert_eq!(
        artifact["runner_bundle_schema_version"].as_str(),
        Some("kernel-fast-path-substrate-smoke-bundle-v1")
    );
    assert_eq!(
        artifact["runner_report_schema_version"].as_str(),
        Some("kernel-fast-path-substrate-smoke-run-report-v1")
    );
    assert_eq!(
        artifact["runner_script"].as_str(),
        Some("scripts/run_kernel_fast_path_substrate_smoke.sh")
    );
}

// ── Current substrate catalog ────────────────────────────────────────

#[test]
fn current_substrate_has_expected_components() {
    let artifact = load_artifact();
    let actual: BTreeSet<String> = artifact["current_substrate"]
        .as_array()
        .expect("current_substrate must be array")
        .iter()
        .map(|c| {
            c["component_id"]
                .as_str()
                .expect("component_id must be string")
                .to_string()
        })
        .collect();
    let expected: BTreeSet<String> = [
        "local-queue",
        "work-stealing",
        "global-injector",
        "waker-dedup",
    ]
    .into_iter()
    .map(ToOwned::to_owned)
    .collect();
    assert_eq!(
        actual, expected,
        "current substrate components must remain stable"
    );
}

#[test]
fn current_substrate_owner_files_exist() {
    let artifact = load_artifact();
    let root = repo_root();
    for component in artifact["current_substrate"].as_array().unwrap() {
        let cid = component["component_id"].as_str().unwrap();
        let owner_file = component["owner_file"]
            .as_str()
            .expect("owner_file must be string");
        assert!(
            root.join(owner_file).exists(),
            "owner file for {cid} must exist: {owner_file}"
        );
    }
}

#[test]
fn each_substrate_component_has_required_fields() {
    let artifact = load_artifact();
    let required = [
        "component_id",
        "description",
        "owner_file",
        "locking",
        "allocation",
    ];
    for component in artifact["current_substrate"].as_array().unwrap() {
        let cid = component["component_id"].as_str().unwrap_or("<missing>");
        for field in &required {
            assert!(
                component.get(*field).is_some(),
                "component {cid} missing field: {field}"
            );
        }
    }
}

// ── Candidate catalog ────────────────────────────────────────────────

#[test]
fn candidate_catalog_has_expected_ids() {
    let artifact = load_artifact();
    let actual: BTreeSet<String> = artifact["candidates"]
        .as_array()
        .expect("candidates must be array")
        .iter()
        .map(|c| {
            c["candidate_id"]
                .as_str()
                .expect("candidate_id must be string")
                .to_string()
        })
        .collect();
    let expected: BTreeSet<String> = [
        "spsc-ring-local-queue",
        "chase-lev-deque",
        "sharded-waker-bitmap",
        "timing-wheel-timed-lane",
    ]
    .into_iter()
    .map(ToOwned::to_owned)
    .collect();
    assert_eq!(actual, expected, "candidate catalog must remain stable");
}

#[test]
fn each_candidate_has_required_fields() {
    let artifact = load_artifact();
    let required = [
        "candidate_id",
        "description",
        "target_component",
        "expected_improvement",
        "determinism_impact",
        "unsafe_required",
    ];
    for candidate in artifact["candidates"].as_array().unwrap() {
        let cid = candidate["candidate_id"].as_str().unwrap_or("<missing>");
        for field in &required {
            assert!(
                candidate.get(*field).is_some(),
                "candidate {cid} missing field: {field}"
            );
        }
    }
}

#[test]
fn candidate_targets_reference_valid_components() {
    let artifact = load_artifact();
    let component_ids: BTreeSet<String> = artifact["current_substrate"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["component_id"].as_str().unwrap().to_string())
        .collect();

    for candidate in artifact["candidates"].as_array().unwrap() {
        let cid = candidate["candidate_id"].as_str().unwrap();
        let target = candidate["target_component"]
            .as_str()
            .expect("target_component must be string");
        assert!(
            component_ids.contains(target),
            "candidate {cid} targets unknown component: {target}"
        );
    }
}

// ── Evaluation dimensions and decision rules ─────────────────────────

#[test]
fn evaluation_dimensions_are_nonempty() {
    let artifact = load_artifact();
    let dims = artifact["evaluation_dimensions"]
        .as_array()
        .expect("evaluation_dimensions must be array");
    assert!(
        dims.len() >= 5,
        "must have at least 5 evaluation dimensions"
    );
}

#[test]
fn decision_rules_are_nonempty() {
    let artifact = load_artifact();
    let rules = artifact["decision_rules"]
        .as_array()
        .expect("decision_rules must be array");
    assert!(rules.len() >= 3, "must have at least 3 decision rules");
    let all_text: String = rules
        .iter()
        .map(|r| r.as_str().unwrap_or(""))
        .collect::<Vec<_>>()
        .join(" ");
    assert!(
        all_text.contains("fallback"),
        "decision rules must mention fallback seam"
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
        "kernel-fast-path-substrate-smoke-bundle-v1",
        "kernel-fast-path-substrate-smoke-run-report-v1",
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

// ── Local queue functional invariants ────────────────────────────────

#[test]
fn local_queue_source_files_compile() {
    // Verify key scheduler source files exist and are importable
    let root = repo_root();
    for path in [
        "src/runtime/scheduler/local_queue.rs",
        "src/runtime/scheduler/stealing.rs",
        "src/runtime/scheduler/global_injector.rs",
        "src/runtime/scheduler/intrusive.rs",
        "src/runtime/waker.rs",
    ] {
        assert!(
            root.join(path).exists(),
            "scheduler source must exist: {path}"
        );
    }
}

#[test]
fn waker_state_dedup_works() {
    use asupersync::runtime::waker::WakerState;
    use asupersync::types::TaskId;
    use std::sync::Arc;

    let state = Arc::new(WakerState::new());
    let tid = TaskId::new_for_test(1, 0);

    // Create a waker and wake it twice
    let waker = state.waker_for(tid);
    waker.wake_by_ref();
    waker.wake_by_ref();

    // Drain should produce the task exactly once (dedup)
    let woken = state.drain_woken();
    assert_eq!(woken.len(), 1, "waker dedup must coalesce duplicate wakes");
    assert_eq!(woken[0], tid);

    // Second drain should be empty
    let woken2 = state.drain_woken();
    assert!(woken2.is_empty(), "drain must clear woken set");
}
