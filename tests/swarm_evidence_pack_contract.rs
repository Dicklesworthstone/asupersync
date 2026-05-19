#![allow(missing_docs)]

use serde_json::Value as JsonValue;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

const ARTIFACT_PATH: &str = "artifacts/swarm_evidence_pack_contract_v1.json";
const CONTRACT_TEST: &str = "tests/swarm_evidence_pack_contract.rs";
const CONTRACT_SCHEMA_VERSION: &str = "swarm-evidence-pack-contract-v1";
const PACK_SCHEMA_VERSION: &str = "swarm-evidence-pack-v1";
const REQUIRED_FIXTURES: [&str; 5] = [
    "happy_path",
    "blocked_tracker",
    "disk_critical_source_only_fallback",
    "stale_in_progress",
    "all_children_closed_epic_closeout",
];

fn repo_path(relative: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(relative)
}

fn artifact() -> JsonValue {
    let path = repo_path(ARTIFACT_PATH);
    let body = std::fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("read {}: {err}", path.display()));
    serde_json::from_str(&body).unwrap_or_else(|err| panic!("parse {}: {err}", path.display()))
}

fn array<'a>(value: &'a JsonValue, key: &str) -> &'a Vec<JsonValue> {
    value
        .get(key)
        .and_then(JsonValue::as_array)
        .unwrap_or_else(|| panic!("{key} must be an array"))
}

fn object<'a>(value: &'a JsonValue, key: &str) -> &'a serde_json::Map<String, JsonValue> {
    value
        .get(key)
        .and_then(JsonValue::as_object)
        .unwrap_or_else(|| panic!("{key} must be an object"))
}

fn string<'a>(value: &'a JsonValue, key: &str) -> &'a str {
    let item = value
        .get(key)
        .and_then(JsonValue::as_str)
        .unwrap_or_else(|| panic!("{key} must be a string"));
    assert!(!item.trim().is_empty(), "{key} must be nonempty");
    item
}

fn bool_value(value: &JsonValue, key: &str) -> bool {
    value
        .get(key)
        .and_then(JsonValue::as_bool)
        .unwrap_or_else(|| panic!("{key} must be a bool"))
}

fn u64_value(value: &JsonValue, key: &str) -> u64 {
    value
        .get(key)
        .and_then(JsonValue::as_u64)
        .unwrap_or_else(|| panic!("{key} must be an unsigned integer"))
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

fn timestamp_utc<'a>(value: &'a JsonValue, key: &str) -> &'a str {
    let timestamp = string(value, key);
    assert!(
        timestamp.ends_with('Z') && timestamp.contains('T'),
        "{key} must be a UTC timestamp ending in Z: {timestamp}"
    );
    timestamp
}

fn fixture<'a>(artifact: &'a JsonValue, fixture_id: &str) -> &'a JsonValue {
    array(artifact, "fixtures")
        .iter()
        .find(|fixture| fixture.get("fixture_id").and_then(JsonValue::as_str) == Some(fixture_id))
        .unwrap_or_else(|| panic!("missing fixture {fixture_id}"))
}

fn pack(fixture: &JsonValue) -> &JsonValue {
    fixture
        .get("pack")
        .unwrap_or_else(|| panic!("{} missing pack", string(fixture, "fixture_id")))
}

fn command_strings(pack: &JsonValue) -> Vec<&str> {
    pack.get("proof_outcomes")
        .and_then(|proof| proof.get("proofs"))
        .and_then(JsonValue::as_array)
        .into_iter()
        .flatten()
        .filter_map(|proof| proof.get("command").and_then(JsonValue::as_str))
        .collect()
}

#[test]
fn artifact_declares_schema_paths_and_report_only_policy() {
    let artifact = artifact();

    assert_eq!(
        artifact.get("schema_version").and_then(JsonValue::as_str),
        Some(CONTRACT_SCHEMA_VERSION)
    );
    assert_eq!(
        artifact
            .get("pack_schema_version")
            .and_then(JsonValue::as_str),
        Some(PACK_SCHEMA_VERSION)
    );
    assert_eq!(string(&artifact, "artifact_path"), ARTIFACT_PATH);
    assert_eq!(string(&artifact, "contract_test"), CONTRACT_TEST);
    timestamp_utc(&artifact, "generated_at_utc");

    let policy = artifact
        .get("side_effect_policy")
        .expect("side_effect_policy");
    assert_eq!(string(policy, "mode"), "report_only");
    for key in [
        "beads_mutation_allowed",
        "agent_mail_mutation_allowed",
        "filesystem_cleanup_allowed",
        "cargo_execution_allowed",
        "local_cargo_fallback_allowed",
    ] {
        assert!(!bool_value(policy, key), "{key} must be forbidden");
    }
}

#[test]
fn artifact_contains_required_sections_and_source_hash_contract() {
    let artifact = artifact();
    let required_sections = string_set(&artifact, "required_sections");
    let required_hashes = string_set(&artifact, "required_source_hashes");

    for section in [
        "ready_queue_state",
        "reservations",
        "dirty_paths",
        "proof_outcomes",
        "disk_pressure",
        "chosen_action",
        "final_closeout",
        "source_hashes",
        "safety_invariants",
    ] {
        assert!(
            required_sections.contains(section),
            "missing required section {section}"
        );
    }

    for section in required_sections {
        if section == "source_hashes" || section == "safety_invariants" {
            continue;
        }
        assert!(
            required_hashes.contains(&section),
            "{section} must have a source hash"
        );
    }
}

#[test]
fn fixtures_cover_all_required_replay_cases() {
    let artifact = artifact();
    let fixture_ids: BTreeSet<_> = array(&artifact, "fixtures")
        .iter()
        .map(|fixture| string(fixture, "fixture_id").to_string())
        .collect();

    for fixture_id in REQUIRED_FIXTURES {
        assert!(
            fixture_ids.contains(fixture_id),
            "missing evidence-pack fixture {fixture_id}"
        );
    }
    assert_eq!(
        fixture_ids.len(),
        REQUIRED_FIXTURES.len(),
        "unexpected fixture drift"
    );
}

#[test]
fn every_fixture_is_a_complete_pack_with_fresh_utc_sources() {
    let artifact = artifact();
    let max_age = u64_value(
        artifact
            .get("timestamp_policy")
            .expect("timestamp_policy must exist"),
        "max_source_age_seconds",
    );
    let required_sections = string_set(&artifact, "required_sections");
    let required_hashes = string_set(&artifact, "required_source_hashes");

    for fixture in array(&artifact, "fixtures") {
        let fixture_id = string(fixture, "fixture_id");
        let pack = pack(fixture);
        assert_eq!(
            pack.get("schema_version").and_then(JsonValue::as_str),
            Some(PACK_SCHEMA_VERSION),
            "{fixture_id} must use the pack schema"
        );
        timestamp_utc(pack, "created_at_utc");

        for section in &required_sections {
            assert!(
                pack.get(section).is_some(),
                "{fixture_id} missing {section}"
            );
        }

        let source_hashes = object(pack, "source_hashes");
        for section in &required_hashes {
            let hash = source_hashes
                .get(section)
                .and_then(JsonValue::as_str)
                .unwrap_or_else(|| panic!("{fixture_id} missing hash for {section}"));
            assert!(
                hash.starts_with("sha256:") && hash.len() > "sha256:".len(),
                "{fixture_id} hash for {section} must be sha256-prefixed"
            );
        }

        for section in [
            "ready_queue_state",
            "reservations",
            "dirty_paths",
            "proof_outcomes",
            "disk_pressure",
            "chosen_action",
            "final_closeout",
        ] {
            let section_value = pack.get(section).expect("section exists");
            timestamp_utc(section_value, "observed_at_utc");
            let age = u64_value(section_value, "evidence_age_seconds");
            if fixture_id != "stale_in_progress" {
                assert!(
                    age <= max_age,
                    "{fixture_id} has unexpectedly stale {section} evidence"
                );
            }
        }
    }
}

#[test]
fn safety_invariants_are_explicit_and_true_for_all_fixtures() {
    let artifact = artifact();
    let invariant_ids = string_set(&artifact, "safety_invariants");

    for fixture in array(&artifact, "fixtures") {
        let fixture_id = string(fixture, "fixture_id");
        let pack = pack(fixture);
        let invariants = object(pack, "safety_invariants");

        for invariant in &invariant_ids {
            let value = invariants
                .get(invariant)
                .and_then(JsonValue::as_bool)
                .unwrap_or_else(|| panic!("{fixture_id} missing invariant {invariant}"));
            assert!(value, "{fixture_id} invariant {invariant} must be true");
        }
    }
}

#[test]
fn fixture_commands_require_rch_and_exclude_destructive_or_local_cargo_paths() {
    let artifact = artifact();
    let forbidden = array(&artifact, "forbidden_command_fragments")
        .iter()
        .map(|entry| entry.as_str().expect("forbidden fragments must be strings"))
        .collect::<Vec<_>>();

    for fixture in array(&artifact, "fixtures") {
        let fixture_id = string(fixture, "fixture_id");
        let pack = pack(fixture);
        for command in command_strings(pack) {
            assert!(
                command.contains("RCH_REQUIRE_REMOTE=1 rch exec --"),
                "{fixture_id} proof command must be remote-required rch: {command}"
            );
            for fragment in &forbidden {
                if fragment.trim_start().starts_with("cargo ") {
                    assert!(
                        !command.starts_with(fragment.trim()),
                        "{fixture_id} command uses local Cargo fallback: {command}"
                    );
                } else {
                    assert!(
                        !command.contains(fragment),
                        "{fixture_id} command contains forbidden fragment {fragment}: {command}"
                    );
                }
            }
        }
    }
}

#[test]
fn chosen_actions_are_known_and_never_authorize_mutation_by_themselves() {
    let artifact = artifact();
    let allowed_actions = string_set(&artifact, "allowed_actions");

    for fixture in array(&artifact, "fixtures") {
        let fixture_id = string(fixture, "fixture_id");
        let chosen = pack(fixture)
            .get("chosen_action")
            .expect("chosen_action must exist");
        let action = string(chosen, "action");
        assert!(
            allowed_actions.contains(action),
            "{fixture_id} has unknown action {action}"
        );
        assert!(
            !bool_value(chosen, "mutation_authorized_by_pack"),
            "{fixture_id} must not authorize mutation from the pack alone"
        );
    }
}

#[test]
fn required_fixture_semantics_are_pinned() {
    let artifact = artifact();

    let blocked = pack(fixture(&artifact, "blocked_tracker"));
    assert!(bool_value(
        blocked.get("reservations").expect("reservations"),
        "tracker_reserved"
    ));
    assert_eq!(
        string(
            blocked.get("chosen_action").expect("chosen_action"),
            "action"
        ),
        "defer_tracker_blocked"
    );
    assert_eq!(
        string(
            blocked.get("final_closeout").expect("final_closeout"),
            "status"
        ),
        "deferred"
    );

    let disk = pack(fixture(&artifact, "disk_critical_source_only_fallback"));
    assert_eq!(
        string(disk.get("disk_pressure").expect("disk_pressure"), "status"),
        "critical"
    );
    assert!(bool_value(
        disk.get("disk_pressure").expect("disk_pressure"),
        "retrieval_blocked"
    ));
    assert_eq!(
        string(disk.get("chosen_action").expect("chosen_action"), "action"),
        "proceed_source_only_without_cargo"
    );
    assert!(!bool_value(
        disk.get("proof_outcomes").expect("proof_outcomes"),
        "local_fallback_detected"
    ));

    let stale = pack(fixture(&artifact, "stale_in_progress"));
    let stale_rows = array(
        stale
            .get("ready_queue_state")
            .expect("ready_queue_state must exist"),
        "stale_in_progress",
    );
    assert_eq!(stale_rows.len(), 1);
    assert!(
        u64_value(&stale_rows[0], "last_updated_age_seconds") > 3600,
        "stale fixture must model an old in-progress owner"
    );
    assert_eq!(
        string(stale.get("chosen_action").expect("chosen_action"), "action"),
        "recommend_reopen_stale_in_progress"
    );

    let epic = pack(fixture(&artifact, "all_children_closed_epic_closeout"));
    let children = array(
        epic.get("ready_queue_state")
            .expect("ready_queue_state must exist"),
        "children",
    );
    assert_eq!(children.len(), 6);
    assert!(
        children
            .iter()
            .all(|child| child.get("status").and_then(JsonValue::as_str) == Some("closed"))
    );
    assert_eq!(
        u64_value(
            epic.get("final_closeout").expect("final_closeout"),
            "open_child_count"
        ),
        0
    );
}

#[test]
fn closeout_contradiction_rules_cover_stale_hash_local_fallback_and_epic_cases() {
    let artifact = artifact();
    let findings: BTreeSet<_> = array(&artifact, "closeout_contradiction_rules")
        .iter()
        .map(|rule| string(rule, "finding").to_string())
        .collect();

    for required in [
        "proof_claimed_with_local_fallback",
        "source_hash_missing",
        "stale_source_snapshot",
        "closeout_missing_commit_or_defer",
        "epic_closeout_has_open_children",
    ] {
        assert!(
            findings.contains(required),
            "missing contradiction rule for {required}"
        );
    }

    for fixture in array(&artifact, "fixtures") {
        let fixture_id = string(fixture, "fixture_id");
        for finding in array(fixture, "expected_findings") {
            let finding = finding
                .as_str()
                .unwrap_or_else(|| panic!("{fixture_id} expected findings must be strings"));
            assert!(
                finding == "tracker_blocked"
                    || finding == "disk_critical_source_only"
                    || finding == "stale_in_progress"
                    || findings.contains(finding),
                "{fixture_id} expected finding {finding} is not known"
            );
        }
    }
}

#[test]
fn validation_declares_remote_required_contract_lane() {
    let artifact = artifact();
    let validation = artifact.get("validation").expect("validation");
    assert_eq!(
        string(validation, "json_probe"),
        "jq empty artifacts/swarm_evidence_pack_contract_v1.json"
    );
    assert_eq!(
        string(validation, "format_check"),
        "rustfmt --edition 2024 --check tests/swarm_evidence_pack_contract.rs"
    );
    let proof = string(validation, "remote_required_contract_test");
    assert!(
        proof.contains("RCH_REQUIRE_REMOTE=1 rch exec --"),
        "contract proof must require remote rch"
    );
    assert!(
        proof.contains("CARGO_TARGET_DIR=/tmp/rch_target_rubyrobin_swarm_evidence_pack"),
        "contract proof must pin the target dir"
    );
    assert!(
        proof.contains("cargo test -p asupersync --test swarm_evidence_pack_contract"),
        "contract proof must target this integration test"
    );
}
