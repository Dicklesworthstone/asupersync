#![allow(missing_docs)]

use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

const AGENTS_PATH: &str = "AGENTS.md";
const MANIFEST_PATH: &str = "artifacts/proof_lane_manifest_v1.json";
const README_PATH: &str = "README.md";
const RUNBOOK_PATH: &str = "docs/fourth_wave_swarm_governor_runbook.md";
const SNAPSHOT_PATH: &str = "artifacts/proof_status_snapshot_v1.json";
const TEST_PATH: &str = "tests/fourth_wave_swarm_governor_runbook_contract.rs";
const FINAL_SIGNOFF_PATH: &str = "artifacts/fourth_wave_governor_final_signoff_v1.json";
const FINAL_SIGNOFF_TEST_PATH: &str = "tests/fourth_wave_governor_final_signoff_contract.rs";
const PROOF_RUNNER_DOC_PATH: &str = "docs/proof_runner_usage.md";

const FOURTH_WAVE_LANES: &[&str] = &[
    "fourth-wave-governor-schema-contract",
    "fourth-wave-governor-policy-engine",
    "fourth-wave-swarm-replay-corpus",
    "fourth-wave-runtime-bridge-contract",
    "fourth-wave-benchmark-contract",
    "fourth-wave-governor-signoff-runbook",
    "fourth-wave-governor-final-signoff",
];

const FOURTH_WAVE_CATEGORIES: &[&str] = &[
    "fourth-wave governor schema proof",
    "fourth-wave governor policy-engine proof",
    "fourth-wave swarm replay corpus",
    "fourth-wave runtime bridge",
    "fourth-wave benchmark no-claim contract",
    "fourth-wave final aggregated signoff",
];

fn repo_path(relative: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(relative)
}

fn read_repo_file(relative: &str) -> String {
    std::fs::read_to_string(repo_path(relative))
        .unwrap_or_else(|error| panic!("read {relative}: {error}"))
}

fn json(relative: &str) -> Value {
    serde_json::from_str(&read_repo_file(relative))
        .unwrap_or_else(|error| panic!("parse {relative}: {error}"))
}

fn array<'a>(value: &'a Value, key: &str) -> &'a Vec<Value> {
    value
        .get(key)
        .and_then(Value::as_array)
        .unwrap_or_else(|| panic!("{key} must be an array"))
}

fn string<'a>(value: &'a Value, key: &str) -> &'a str {
    let text = value
        .get(key)
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("{key} must be a string"));
    assert!(!text.trim().is_empty(), "{key} must be nonempty");
    text
}

fn string_set(value: &Value, key: &str) -> BTreeSet<String> {
    array(value, key)
        .iter()
        .map(|item| {
            item.as_str()
                .unwrap_or_else(|| panic!("{key} entries must be strings"))
                .to_string()
        })
        .collect()
}

fn assert_contains_all(label: &str, text: &str, markers: &[&str]) {
    for marker in markers {
        assert!(text.contains(marker), "{label} missing {marker}");
    }
}

fn manifest_lanes(manifest: &Value) -> BTreeMap<String, Value> {
    array(manifest, "lanes")
        .iter()
        .map(|lane| (string(lane, "lane_id").to_string(), lane.clone()))
        .collect()
}

fn snapshot_claims(snapshot: &Value) -> BTreeMap<String, Value> {
    array(snapshot, "claim_categories")
        .iter()
        .map(|row| (string(row, "category").to_string(), row.clone()))
        .collect()
}

fn assert_remote_required_cargo(command: &str, lane_id: &str) {
    assert!(
        command.starts_with("RCH_REQUIRE_REMOTE=1 rch exec -- env "),
        "{lane_id}: command must be remote-required RCH"
    );
    assert!(
        command.contains("CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_fourth_wave_"),
        "{lane_id}: command must isolate a fourth-wave target dir"
    );
    assert!(
        command.contains(" cargo "),
        "{lane_id}: command must route Cargo through RCH"
    );
    for forbidden in [
        "RCH_ALLOW_LOCAL=1",
        "RCH_REQUIRE_REMOTE=0",
        "rch exec -- cargo",
    ] {
        assert!(
            !command.contains(forbidden),
            "{lane_id}: command contains forbidden local/fallback marker {forbidden}"
        );
    }
}

#[test]
fn runbook_names_canonical_surfaces_and_single_lane_command() {
    let runbook = read_repo_file(RUNBOOK_PATH);
    assert_contains_all(
        "runbook",
        &runbook,
        &[
            RUNBOOK_PATH,
            TEST_PATH,
            "artifacts/fourth_wave_swarm_governor_contract_v1.json",
            "artifacts/swarm_workload_scenario_corpus_v1.json",
            "artifacts/slo_policy_bundle_contract_v1.json",
            "artifacts/fourth_wave_swarm_governor_benchmark_contract_v1.json",
            FINAL_SIGNOFF_PATH,
            "artifacts/proof_lane_manifest_v1.json",
            "artifacts/proof_status_snapshot_v1.json",
            "fourth-wave-governor-signoff-runbook",
            "fourth-wave-governor-final-signoff",
            "cargo test -p asupersync --test fourth_wave_swarm_governor_runbook_contract",
            "cargo test -p asupersync --test fourth_wave_governor_final_signoff_contract",
        ],
    );
    assert_contains_all(
        "contract test",
        &read_repo_file(TEST_PATH),
        FOURTH_WAVE_LANES,
    );
}

#[test]
fn proof_manifest_declares_fourth_wave_lanes_with_remote_only_commands() {
    let manifest = json(MANIFEST_PATH);
    let lanes = manifest_lanes(&manifest);
    let required = string_set(&manifest, "required_guarantee_ids");

    for lane_id in FOURTH_WAVE_LANES {
        let lane = lanes
            .get(*lane_id)
            .unwrap_or_else(|| panic!("missing lane {lane_id}"));
        assert_eq!(
            string(lane, "resource_envelope_class"),
            "artifact-contract-medium",
            "{lane_id}: fourth-wave lanes should remain focused artifact contracts"
        );
        assert_remote_required_cargo(string(lane, "command"), lane_id);
        assert!(
            required.contains(*lane_id),
            "{lane_id}: required guarantee ids must include the lane-scoped guarantee"
        );
        assert!(
            string_set(lane, "guarantee_ids").contains(*lane_id),
            "{lane_id}: guarantee ids must include the matching guarantee"
        );
    }

    let signoff = lanes
        .get("fourth-wave-governor-signoff-runbook")
        .expect("signoff lane");
    for required_path in [
        RUNBOOK_PATH,
        TEST_PATH,
        MANIFEST_PATH,
        SNAPSHOT_PATH,
        README_PATH,
        AGENTS_PATH,
        PROOF_RUNNER_DOC_PATH,
    ] {
        assert!(
            string_set(signoff, "source_paths").contains(required_path),
            "signoff lane missing source path {required_path}"
        );
    }
    assert!(
        string(signoff, "explicit_not_covered").contains("fresh benchmark improvement"),
        "signoff lane must preserve benchmark non-claim text"
    );

    let final_signoff = lanes
        .get("fourth-wave-governor-final-signoff")
        .expect("final signoff lane");
    for required_path in [
        FINAL_SIGNOFF_PATH,
        FINAL_SIGNOFF_TEST_PATH,
        RUNBOOK_PATH,
        MANIFEST_PATH,
        SNAPSHOT_PATH,
        README_PATH,
        AGENTS_PATH,
    ] {
        assert!(
            string_set(final_signoff, "source_paths").contains(required_path),
            "final signoff lane missing source path {required_path}"
        );
    }
    assert!(
        string(final_signoff, "explicit_not_covered").contains("production-on-by-default")
            && string(final_signoff, "explicit_not_covered")
                .contains("fresh benchmark improvement"),
        "final signoff lane must preserve broad non-claim text"
    );
}

#[test]
fn status_snapshot_keeps_fourth_wave_claims_separate_and_scoped() {
    let snapshot = json(SNAPSHOT_PATH);
    let claims = snapshot_claims(&snapshot);
    let required_categories = string_set(&snapshot, "required_claim_categories");

    for category in FOURTH_WAVE_CATEGORIES {
        assert!(
            required_categories.contains(*category),
            "snapshot required categories missing {category}"
        );
        let claim = claims
            .get(*category)
            .unwrap_or_else(|| panic!("snapshot missing claim category {category}"));
        assert_eq!(string(claim, "proof_evidence_status"), "blocked");
        assert_contains_all(
            "blocked frontier",
            string(&claim["blocked_frontier"], "required_followup"),
            &["Rerun", "fourth-wave", "clean committed main"],
        );
        for command in string_set(claim, "proof_commands") {
            assert_remote_required_cargo(&command, category);
        }
    }

    let benchmark = claims
        .get("fourth-wave benchmark no-claim contract")
        .expect("benchmark claim");
    assert_eq!(string(benchmark, "status"), "yellow_scoped");
    assert_contains_all(
        "benchmark notes",
        string(benchmark, "notes"),
        &[
            "no-claim report",
            "not a fresh benchmark result",
            "does not prove p95 improvement",
            "production-on-by-default control",
        ],
    );

    let aggregate = claims
        .get("fourth-wave final aggregated signoff")
        .expect("aggregate claim");
    assert_eq!(string(aggregate, "status"), "yellow_scoped");
    assert_eq!(string_set(aggregate, "manifest_lane_ids"), lane_set());
    assert_eq!(string_set(aggregate, "manifest_guarantee_ids"), lane_set());
    assert_contains_all(
        "aggregate notes",
        string(aggregate, "notes"),
        &[
            "Yellow-scoped aggregate signoff",
            "operator checklist",
            "production-on-by-default control",
            "live performance improvement",
            "broad workspace health",
        ],
    );
}

#[test]
fn readme_agents_and_proof_runner_point_to_the_runbook_and_markers() {
    let readme = read_repo_file(README_PATH);
    let agents = read_repo_file(AGENTS_PATH);
    let proof_runner = read_repo_file(PROOF_RUNNER_DOC_PATH);

    for (label, text) in [
        ("README", readme.as_str()),
        ("AGENTS", agents.as_str()),
        ("proof runner docs", proof_runner.as_str()),
    ] {
        assert_contains_all(
            label,
            text,
            &[
                RUNBOOK_PATH,
                "fourth-wave governor proof map",
                "fourth-wave-governor-signoff-runbook",
                "fourth-wave-governor-final-signoff",
                "fourth-wave final aggregated signoff",
                "fourth-wave benchmark no-claim contract",
                "no fresh benchmark result",
            ],
        );
    }
}

#[test]
fn runbook_preserves_operator_safety_no_local_fallback_and_rollback() {
    let runbook = read_repo_file(RUNBOOK_PATH);
    assert_contains_all(
        "runbook",
        &runbook,
        &[
            "git status --short --branch",
            "file_reservation_paths",
            "renew_file_reservations",
            "release_file_reservations",
            "Agent Mail closeout",
            "git push origin main",
            "git push origin main:master",
            "Leave peer dirt unstaged",
            "RCH_REQUIRE_REMOTE=1 rch exec -- env",
            "No local fallback",
            "[RCH] local",
            "Executing command locally",
            "local fallback accepted",
            "zero-test exact filter",
            "brownout_optional_work",
            "defer_no_remote_worker",
            "fail_closed_local_rch_fallback",
            "SloRuntimePolicyBridge::evaluate_fourth_wave",
            "Stop calling the fourth-wave bridge",
            "parent_close_allowed=false",
            "no_win_rerun_required",
            "dirty shared-main peer work",
            "do not delete",
            "production-on-by-default",
            "RCH fleet availability is proven",
        ],
    );
}

fn lane_set() -> BTreeSet<String> {
    FOURTH_WAVE_LANES
        .iter()
        .map(|lane| (*lane).to_string())
        .collect()
}
