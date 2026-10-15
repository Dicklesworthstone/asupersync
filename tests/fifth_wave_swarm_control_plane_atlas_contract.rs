#![allow(missing_docs)]

use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

const AGENTS_PATH: &str = "AGENTS.md";
const ATLAS_PATH: &str = "artifacts/fifth_wave_swarm_control_plane_atlas_v1.json";
const FOURTH_WAVE_SIGNOFF_PATH: &str = "artifacts/fourth_wave_governor_final_signoff_v1.json";
const FOURTH_WAVE_RUNBOOK_PATH: &str = "docs/fourth_wave_swarm_governor_runbook.md";
const MANIFEST_PATH: &str = "artifacts/proof_lane_manifest_v1.json";
const PROOF_STATUS_SNAPSHOT_PATH: &str = "artifacts/proof_status_snapshot_v1.json";
const README_PATH: &str = "README.md";
const TEST_PATH: &str = "tests/fifth_wave_swarm_control_plane_atlas_contract.rs";

const CHILD_BEADS: &[&str] = &[
    "asupersync-rch-proof-freshness-broker-u9iy0g",
    "asupersync-numa-scheduler-locality-lab-zhvkr9",
    "asupersync-cancellation-storm-replay-corpus-z7hfs6",
    "asupersync-capacity-ticket-agent-admission-od29tn",
    "asupersync-live-swarm-telemetry-heatmap-wt9b4r",
];

const FORBIDDEN_COVER_CLAIMS: &[&str] = &[
    "performance improvement",
    "no regression",
    "broad workspace health",
    "release readiness",
    "live rch fleet availability",
    "production-on-by-default",
    "fourth-wave governor",
];

const REQUIRED_FAILURE_FIXTURES: &[&str] = &[
    "missing-child-proof-command",
    "local-fallback-authorized",
    "missing-no-claim-boundary",
    "broad-performance-claim",
    "fourth-wave-duplication",
];

fn repo_path(relative: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(relative)
}

fn read_repo_file(relative: &str) -> String {
    std::fs::read_to_string(repo_path(relative))
        .unwrap_or_else(|error| panic!("read {relative}: {error}"))
}

fn atlas() -> Value {
    serde_json::from_str(&read_repo_file(ATLAS_PATH))
        .unwrap_or_else(|error| panic!("parse {ATLAS_PATH}: {error}"))
}

fn array<'a>(value: &'a Value, key: &str) -> &'a Vec<Value> {
    value
        .get(key)
        .and_then(Value::as_array)
        .unwrap_or_else(|| panic!("{key} must be an array"))
}

fn object<'a>(value: &'a Value, key: &str) -> &'a serde_json::Map<String, Value> {
    value
        .get(key)
        .and_then(Value::as_object)
        .unwrap_or_else(|| panic!("{key} must be an object"))
}

fn string<'a>(value: &'a Value, key: &str) -> &'a str {
    let text = value
        .get(key)
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("{key} must be a string"));
    assert!(!text.trim().is_empty(), "{key} must be nonempty");
    text
}

fn bool_field(value: &Value, key: &str) -> bool {
    value
        .get(key)
        .and_then(Value::as_bool)
        .unwrap_or_else(|| panic!("{key} must be a bool"))
}

fn u64_field(value: &Value, key: &str) -> u64 {
    value
        .get(key)
        .and_then(Value::as_u64)
        .unwrap_or_else(|| panic!("{key} must be a u64"))
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

fn rows_by_id<'a>(value: &'a Value, key: &str, id_key: &str) -> BTreeMap<String, &'a Value> {
    array(value, key)
        .iter()
        .map(|row| (string(row, id_key).to_string(), row))
        .collect()
}

fn assert_remote_required_cargo_command(command: &str, target_dir: &str) {
    assert!(
        command.starts_with("RCH_REQUIRE_REMOTE=1 rch exec -- env "),
        "command must be remote-required RCH: {command}"
    );
    assert!(
        command.contains(" cargo test "),
        "command must route Cargo tests through RCH: {command}"
    );
    assert!(
        command.contains("CARGO_INCREMENTAL=0"),
        "command must disable incremental compilation: {command}"
    );
    assert!(
        command.contains("CARGO_PROFILE_TEST_DEBUG=0"),
        "command must keep test debug output light: {command}"
    );
    assert!(
        command.contains("RUSTFLAGS='-D warnings -C debuginfo=0'"),
        "command must fail warnings and trim debuginfo: {command}"
    );
    assert!(
        command.contains(target_dir),
        "command must include its target dir {target_dir}: {command}"
    );
    assert!(
        target_dir.starts_with("${TMPDIR:-/tmp}/rch_target_fifth_wave_"),
        "target dir must be fifth-wave scoped: {target_dir}"
    );
    for forbidden in [
        "RCH_ALLOW_LOCAL=1",
        "RCH_REQUIRE_REMOTE=0",
        "local fallback",
        "executing locally",
    ] {
        assert!(
            !command.contains(forbidden),
            "command contains forbidden fallback marker {forbidden}: {command}"
        );
    }
}

fn assert_no_broad_covers(row: &Value) {
    for cover in string_set(row, "covers") {
        let normalized = cover.to_ascii_lowercase();
        for forbidden in FORBIDDEN_COVER_CLAIMS {
            assert!(
                !normalized.contains(forbidden),
                "{} cover claims forbidden broad proof: {cover}",
                string(row, "lane_id")
            );
        }
    }
}

#[test]
fn atlas_declares_sources_fourth_wave_inputs_and_contract_lane() {
    let atlas = atlas();
    assert_eq!(
        string(&atlas, "schema_version"),
        "fifth-wave-swarm-control-plane-atlas-v1"
    );
    assert_eq!(
        string(&atlas, "bead_id"),
        "asupersync-fifth-wave-swarm-atlas-qkc2qs"
    );

    let source = object(&atlas, "source_of_truth");
    for (key, expected) in [
        ("atlas_artifact", ATLAS_PATH),
        ("contract_test", TEST_PATH),
        ("proof_lane_manifest", MANIFEST_PATH),
        ("proof_status_snapshot", PROOF_STATUS_SNAPSHOT_PATH),
        ("fourth_wave_runbook", FOURTH_WAVE_RUNBOOK_PATH),
        ("fourth_wave_final_signoff", FOURTH_WAVE_SIGNOFF_PATH),
        ("agent_instructions", AGENTS_PATH),
        ("readme", README_PATH),
    ] {
        assert_eq!(
            source
                .get(key)
                .and_then(Value::as_str)
                .unwrap_or_else(|| panic!("source_of_truth.{key}")),
            expected
        );
        assert!(
            repo_path(expected).exists(),
            "source_of_truth.{key} path must exist: {expected}"
        );
    }

    let fourth_inputs = rows_by_id(&atlas, "fourth_wave_inputs", "input_id");
    for required in [
        "fourth-wave-governor-runbook",
        "fourth-wave-final-signoff",
        "proof-lane-manifest",
        "proof-status-snapshot",
        "swarm-proof-lane-planner",
    ] {
        let row = fourth_inputs
            .get(required)
            .unwrap_or_else(|| panic!("missing fourth-wave input {required}"));
        assert!(
            bool_field(row, "not_reopened_by_fifth_wave"),
            "{required} must be consumed without reopening fourth-wave scope"
        );
        assert!(
            repo_path(string(row, "path")).exists(),
            "{required} path must exist"
        );
    }

    let contract_lane = &atlas["atlas_contract_lane"];
    assert_eq!(
        string(contract_lane, "owner_bead"),
        "asupersync-fifth-wave-swarm-atlas-qkc2qs"
    );
    let envelope = contract_lane
        .get("resource_envelope")
        .unwrap_or_else(|| panic!("atlas_contract_lane missing resource_envelope"));
    assert!(!object(contract_lane, "resource_envelope").is_empty());
    assert!(bool_field(envelope, "remote_required"));
    assert!(!bool_field(envelope, "local_fallback_allowed"));
    assert_remote_required_cargo_command(
        string(contract_lane, "proof_command"),
        string(envelope, "target_dir"),
    );
    assert_no_broad_covers(contract_lane);
}

#[test]
fn child_lanes_have_remote_proofs_resource_envelopes_and_no_claim_boundaries() {
    let atlas = atlas();
    let child_rows = rows_by_id(&atlas, "child_lanes", "owner_bead");
    assert_eq!(
        child_rows.len(),
        CHILD_BEADS.len(),
        "atlas must map exactly the fifth-wave child beads"
    );

    for bead in CHILD_BEADS {
        let row = child_rows
            .get(*bead)
            .unwrap_or_else(|| panic!("missing child bead {bead}"));
        let lane_id = string(row, "lane_id");
        assert!(
            lane_id.starts_with("fifth-wave-"),
            "{bead} lane must stay in fifth-wave scope"
        );
        assert!(
            !lane_id.starts_with("fourth-wave-"),
            "{bead} must not duplicate a fourth-wave lane id"
        );
        let source_surfaces = string_set(row, "source_surfaces");
        assert!(
            source_surfaces.len() >= 3,
            "{bead} must inventory current source surfaces"
        );
        for surface in &source_surfaces {
            assert!(
                repo_path(surface).exists(),
                "{bead} source surface must exist: {surface}"
            );
        }
        assert!(
            string_set(row, "target_artifacts").len() >= 2,
            "{bead} must declare future artifacts/tests"
        );

        let envelope = row
            .get("resource_envelope")
            .unwrap_or_else(|| panic!("{bead} missing resource_envelope"));
        assert!(!object(row, "resource_envelope").is_empty());
        assert!(
            bool_field(envelope, "remote_required"),
            "{bead} must require remote RCH"
        );
        assert!(
            !bool_field(envelope, "local_fallback_allowed"),
            "{bead} must refuse local fallback"
        );
        assert!(
            u64_field(envelope, "timeout_seconds") >= 900,
            "{bead} timeout must be explicit"
        );
        assert!(
            u64_field(envelope, "memory_mb") >= 4096,
            "{bead} memory envelope must be explicit"
        );
        assert_remote_required_cargo_command(
            string(row, "proof_command"),
            string(envelope, "target_dir"),
        );

        let no_claims = string_set(row, "does_not_cover");
        assert!(
            no_claims.len() >= 4,
            "{bead} must carry multiple no-claim boundaries"
        );
        assert!(
            no_claims
                .iter()
                .all(|claim| claim.to_ascii_lowercase().starts_with("does not ")),
            "{bead} no-claim rows must be explicit does-not-cover statements"
        );
        assert_no_broad_covers(row);
    }
}

#[test]
fn failure_fixtures_and_non_goals_fail_closed_on_broad_claims() {
    let atlas = atlas();
    let fixtures = rows_by_id(&atlas, "failure_fixtures", "fixture_id");
    for fixture_id in REQUIRED_FAILURE_FIXTURES {
        let row = fixtures
            .get(*fixture_id)
            .unwrap_or_else(|| panic!("missing failure fixture {fixture_id}"));
        assert_eq!(string(row, "expected_verdict"), "fail_closed");
        assert!(!string(row, "expected_reason").trim().is_empty());
    }

    let non_goals = string_set(&atlas, "non_goals");
    for required in [
        "does not implement the fourth-wave governor",
        "does not close asupersync-86fe9v or asupersync-86fe9v.8",
        "does not prove performance improvement",
        "does not prove no regression",
        "does not prove broad workspace health",
        "does not prove release readiness",
        "does not prove live RCH fleet availability",
        "does not authorize local Cargo fallback",
        "does not create branches, worktrees, scratch clones, or non-main refs",
    ] {
        assert!(non_goals.contains(required), "missing non-goal: {required}");
    }

    for row in array(&atlas, "closeout_requirements") {
        let requirement = row
            .as_str()
            .expect("closeout_requirements entries must be strings");
        assert!(
            !requirement.trim().is_empty(),
            "closeout requirement must be nonempty"
        );
    }
}
