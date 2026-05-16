#![allow(missing_docs)]

use serde_json::Value as JsonValue;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Command;

const COVERAGE_PATH: &str = "artifacts/formal_wave2_refinement_coverage_v1.json";
const README_PATH: &str = "README.md";
const FORMAL_README_PATH: &str = "formal/README.md";

fn repo_path(relative: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(relative)
}

fn read_repo_file(relative: &str) -> String {
    std::fs::read_to_string(repo_path(relative))
        .unwrap_or_else(|err| panic!("read {relative}: {err}"))
}

fn coverage() -> JsonValue {
    serde_json::from_str(&read_repo_file(COVERAGE_PATH))
        .unwrap_or_else(|err| panic!("parse {COVERAGE_PATH}: {err}"))
}

fn array<'a>(value: &'a JsonValue, key: &str) -> &'a Vec<JsonValue> {
    value
        .get(key)
        .and_then(JsonValue::as_array)
        .unwrap_or_else(|| panic!("{key} must be an array"))
}

fn nonempty_string<'a>(value: &'a JsonValue, key: &str) -> &'a str {
    let item = value
        .get(key)
        .and_then(JsonValue::as_str)
        .unwrap_or_else(|| panic!("{key} must be a string"));
    assert!(!item.trim().is_empty(), "{key} must be nonempty");
    item
}

fn string_set(value: &JsonValue, key: &str) -> BTreeSet<String> {
    array(value, key)
        .iter()
        .map(|entry| {
            entry
                .as_str()
                .unwrap_or_else(|| panic!("{key} entries must be strings"))
                .to_string()
        })
        .collect()
}

#[test]
fn manifest_has_stable_schema_and_required_lanes() {
    let coverage = coverage();
    assert_eq!(
        coverage.get("schema_version").and_then(JsonValue::as_str),
        Some("formal-wave2-refinement-coverage-v1")
    );
    assert_eq!(
        coverage.get("bead_id").and_then(JsonValue::as_str),
        Some("asupersync-i6uzso")
    );
    assert_eq!(
        coverage.get("wave_id").and_then(JsonValue::as_str),
        Some("reality-check-wave2")
    );

    let runner = nonempty_string(&coverage, "runner_script");
    assert!(
        repo_path(runner).is_file(),
        "runner script must exist at {runner}"
    );

    let lanes = array(&coverage, "lane_rows");
    let lane_ids = lanes
        .iter()
        .map(|lane| nonempty_string(lane, "lane_id").to_string())
        .collect::<BTreeSet<_>>();
    for required in [
        "massive_swarm_capacity_envelope",
        "remote_transport_lifecycle",
        "http3_qpack_instruction_streams",
        "wasm_service_worker_direct_runtime",
        "wasm_shared_worker_direct_runtime",
        "browser_native_message_and_stream_apis",
        "browser_rust_runtime_api_stability",
        "web_middleware_streaming",
        "filesystem_parity_cancellation",
        "messaging_real_broker_e2e",
    ] {
        assert!(
            lane_ids.contains(required),
            "missing wave2 formal coverage lane {required}"
        );
    }
}

#[test]
fn lane_rows_have_valid_tiers_invariants_and_owner_beads() {
    let coverage = coverage();
    let proof_tiers = string_set(&coverage, "proof_tier_vocabulary");
    let core_invariants = string_set(&coverage, "canonical_core_invariants");
    let mut seen_lanes = BTreeSet::new();

    for lane in array(&coverage, "lane_rows") {
        let lane_id = nonempty_string(lane, "lane_id");
        assert!(
            seen_lanes.insert(lane_id.to_string()),
            "duplicate lane {lane_id}"
        );

        let owner = nonempty_string(lane, "owner_bead_id");
        assert!(
            owner.starts_with("asupersync-"),
            "{lane_id}: owner bead must be canonical"
        );

        let tier = nonempty_string(lane, "proof_tier");
        assert!(proof_tiers.contains(tier), "{lane_id}: unknown tier {tier}");

        for invariant in array(lane, "invariant_ids") {
            let invariant = invariant.as_str().expect("invariant id string");
            assert!(
                core_invariants.contains(invariant),
                "{lane_id}: unknown invariant {invariant}"
            );
        }
        assert!(
            !array(lane, "theorem_names").is_empty(),
            "{lane_id}: theorem names must be linked"
        );
        assert!(
            !array(lane, "model_states").is_empty(),
            "{lane_id}: model states must be linked"
        );
    }
}

#[test]
fn lane_evidence_paths_exist_or_fail_closed_with_owner() {
    let coverage = coverage();

    for lane in array(&coverage, "lane_rows") {
        let lane_id = nonempty_string(lane, "lane_id");
        for key in [
            "model_artifacts",
            "source_paths",
            "runtime_tests",
            "e2e_artifacts",
        ] {
            for path in array(lane, key) {
                let path = path.as_str().expect("path entries must be strings");
                assert!(
                    repo_path(path).exists(),
                    "{lane_id}: {key} path does not exist: {path}"
                );
            }
        }

        let tier = nonempty_string(lane, "proof_tier");
        let missing = array(lane, "missing_evidence");
        if matches!(
            tier,
            "lean-checked" | "tla-checked" | "lab-oracle-backed" | "artifact-contract-backed"
        ) {
            assert!(
                missing.is_empty(),
                "{lane_id}: strong proof tier cannot carry missing evidence"
            );
            assert!(
                !array(lane, "e2e_artifacts").is_empty(),
                "{lane_id}: strong proof tier needs committed E2E artifact"
            );
        } else {
            assert!(
                !missing.is_empty(),
                "{lane_id}: weak proof tier must inventory missing evidence"
            );
            for item in missing {
                let owner = nonempty_string(item, "owner_bead_id");
                assert!(
                    owner.starts_with("asupersync-"),
                    "{lane_id}: missing evidence must name owner bead"
                );
                nonempty_string(item, "required_evidence");
            }
        }
    }
}

#[test]
fn cargo_and_lean_commands_are_rch_offloaded() {
    let coverage = coverage();

    for lane in array(&coverage, "lane_rows") {
        let lane_id = nonempty_string(lane, "lane_id");
        for command in array(lane, "proof_commands") {
            let command = command.as_str().expect("command entries must be strings");
            assert!(
                !command.trim().is_empty(),
                "{lane_id}: proof command must be nonempty"
            );
            if command.contains("cargo ") {
                assert!(
                    command.contains("rch exec -- env ") && command.contains("CARGO_TARGET_DIR="),
                    "{lane_id}: Cargo proof command must use rch env target dir: {command}"
                );
            }
            if command.contains("lake build") {
                assert!(
                    command.contains("rch exec --"),
                    "{lane_id}: Lean proof command must use rch: {command}"
                );
            }
            for forbidden in ["password=", "token=", "secret=", "bearer "] {
                assert!(
                    !command.to_ascii_lowercase().contains(forbidden),
                    "{lane_id}: command appears to leak sensitive field {forbidden}"
                );
            }
        }
    }
}

#[test]
fn docs_keep_wave2_formal_claims_tiered() {
    let coverage = coverage();
    let doc_contract = coverage
        .get("doc_truth_contract")
        .expect("doc_truth_contract object");
    let readme = read_repo_file(README_PATH);
    let formal_readme = read_repo_file(FORMAL_README_PATH);
    let combined = format!("{readme}\n{formal_readme}");

    for phrase in array(doc_contract, "required_phrases") {
        let phrase = phrase.as_str().expect("required phrase string");
        assert!(
            combined.contains(phrase),
            "docs must contain required truth phrase {phrase}"
        );
    }
    for forbidden in array(doc_contract, "forbidden_claims") {
        let forbidden = forbidden.as_str().expect("forbidden claim string");
        assert!(
            !combined.contains(forbidden),
            "docs must not overclaim: {forbidden}"
        );
    }
}

#[test]
fn runner_emits_required_structured_fields_and_report() {
    let coverage = coverage();
    let runner = nonempty_string(&coverage, "runner_script");
    let output_root = repo_path("target/formal-wave2-refinement-coverage-contract-test");
    let output = Command::new("bash")
        .arg(repo_path(runner))
        .arg("--output-root")
        .arg(&output_root)
        .output()
        .unwrap_or_else(|err| panic!("run {runner}: {err}"));
    assert!(
        output.status.success(),
        "runner failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let report_path = output_root
        .join("asupersync-i6uzso")
        .join("coverage-report.json");
    assert!(
        report_path.is_file(),
        "runner must write report at {}",
        report_path.display()
    );
    let report: JsonValue = serde_json::from_str(
        &std::fs::read_to_string(&report_path)
            .unwrap_or_else(|err| panic!("read runner report: {err}")),
    )
    .unwrap_or_else(|err| panic!("parse runner report: {err}"));
    assert_eq!(
        report.get("schema_version").and_then(JsonValue::as_str),
        Some("formal-wave2-refinement-coverage-report-v1")
    );
    assert_eq!(
        report.get("verdict").and_then(JsonValue::as_str),
        Some("passed")
    );

    let required_fields = string_set(&coverage, "required_log_fields");
    let first_row = array(&report, "rows")
        .first()
        .expect("runner report must include rows");
    let actual_fields = first_row
        .as_object()
        .expect("runner row must be object")
        .keys()
        .cloned()
        .collect::<BTreeSet<_>>();
    for field in required_fields {
        assert!(
            actual_fields.contains(&field),
            "runner row must contain required field {field}"
        );
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("bead_id=asupersync-i6uzso"),
        "runner stdout must include bead id"
    );
    assert!(
        stdout.contains("scenario_id=summary"),
        "runner stdout must include summary"
    );
}
