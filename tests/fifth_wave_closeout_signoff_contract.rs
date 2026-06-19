#![allow(clippy::nursery, clippy::pedantic, missing_docs)]

use serde_json::Value;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

const ARTIFACT_PATH: &str = "artifacts/fifth_wave_closeout_signoff_v1.json";
const DOCS_PATH: &str = "docs/fifth_wave_closeout_signoff.md";
const TEST_PATH: &str = "tests/fifth_wave_closeout_signoff_contract.rs";
const BEAD_ID: &str = "asupersync-idea-wizard-fifth-wave-3gaiun.16";
const PARENT_BEAD_ID: &str = "asupersync-idea-wizard-fifth-wave-3gaiun";
const TARGET_DIR: &str = "${TMPDIR:-/tmp}/rch_target_fifth_wave_closeout_signoff";

fn repo_path(relative: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(relative)
}

fn read_repo_file(relative: &str) -> String {
    std::fs::read_to_string(repo_path(relative))
        .unwrap_or_else(|error| panic!("read {relative}: {error}"))
}

fn artifact() -> Value {
    serde_json::from_str(&read_repo_file(ARTIFACT_PATH))
        .unwrap_or_else(|error| panic!("parse {ARTIFACT_PATH}: {error}"))
}

fn array<'a>(value: &'a Value, key: &str) -> &'a [Value] {
    value
        .get(key)
        .and_then(Value::as_array)
        .map_or_else(|| panic!("{key} must be an array"), Vec::as_slice)
}

fn object<'a>(value: &'a Value, key: &str) -> &'a Value {
    let object = value.get(key).unwrap_or_else(|| panic!("{key} must exist"));
    assert!(object.is_object(), "{key} must be an object");
    object
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

fn string_set(value: &Value, key: &str) -> BTreeSet<String> {
    array(value, key)
        .iter()
        .map(|entry| {
            entry
                .as_str()
                .unwrap_or_else(|| panic!("{key} entries must be strings"))
                .to_owned()
        })
        .collect()
}

fn assert_live_path(path: &str) {
    assert!(repo_path(path).exists(), "path must exist: {path}");
}

fn assert_remote_required_cargo_command(command: &str) {
    assert!(
        command.starts_with("RCH_REQUIRE_REMOTE=1 rch exec -- env "),
        "proof command must require remote RCH: {command}"
    );
    for required in [
        TARGET_DIR,
        "CARGO_INCREMENTAL=0",
        "CARGO_PROFILE_TEST_DEBUG=0",
        "RUSTFLAGS='-D warnings -C debuginfo=0'",
        "cargo test -p asupersync --test fifth_wave_closeout_signoff_contract",
        "--no-default-features",
        "-- --nocapture",
    ] {
        assert!(
            command.contains(required),
            "proof command missing {required}: {command}"
        );
    }
    for forbidden in [
        "RCH_ALLOW_LOCAL=1",
        "RCH_REQUIRE_REMOTE=0",
        "local fallback",
        "executing locally",
        "cargo test -p asupersync --test fifth_wave_closeout_signoff_contract -- --nocapture",
    ] {
        assert!(
            !command.contains(forbidden),
            "proof command contains forbidden fallback marker {forbidden}: {command}"
        );
    }
}

fn all_decisions(artifact: &Value) -> Vec<&Value> {
    array(artifact, "top_five_decisions")
        .iter()
        .chain(array(artifact, "next_ten_decisions"))
        .collect()
}

fn decision_by_idea_id<'a>(artifact: &'a Value, idea_id: &str) -> &'a Value {
    all_decisions(artifact)
        .into_iter()
        .find(|row| string(row, "idea_id") == idea_id)
        .unwrap_or_else(|| panic!("missing decision row {idea_id}"))
}

#[test]
fn artifact_docs_and_remote_validation_are_wired() {
    let artifact = artifact();
    assert_eq!(
        artifact.get("schema_version").and_then(Value::as_str),
        Some("fifth-wave-closeout-signoff-v1")
    );
    assert_eq!(
        artifact.get("bead_id").and_then(Value::as_str),
        Some(BEAD_ID)
    );
    assert_eq!(
        artifact.get("parent_bead_id").and_then(Value::as_str),
        Some(PARENT_BEAD_ID)
    );
    assert_eq!(
        artifact.get("artifact_path").and_then(Value::as_str),
        Some(ARTIFACT_PATH)
    );
    assert_eq!(
        artifact.get("docs_path").and_then(Value::as_str),
        Some(DOCS_PATH)
    );
    assert_eq!(
        artifact.get("contract_test").and_then(Value::as_str),
        Some(TEST_PATH)
    );

    let docs = read_repo_file(DOCS_PATH);
    assert!(docs.contains(ARTIFACT_PATH), "docs must link artifact");
    assert!(docs.contains(BEAD_ID), "docs must link closeout bead");
    for marker in array(&artifact, "docs_markers") {
        let marker = marker.as_str().expect("docs marker string");
        assert!(docs.contains(marker), "docs missing marker {marker}");
    }

    let validation = object(&artifact, "validation");
    assert_remote_required_cargo_command(string(validation, "rch_command"));
    assert!(bool_field(validation, "no_local_cargo_fallback"));
}

#[test]
fn inventory_is_generated_and_fails_closed() {
    let artifact = artifact();
    let inventory = object(&artifact, "inventory_generation");
    assert!(
        !bool_field(inventory, "manual_status_table_accepted"),
        "manual tables must not be accepted as proof"
    );

    let commands = array(inventory, "generated_from")
        .iter()
        .map(|row| string(row, "command").to_owned())
        .collect::<BTreeSet<_>>();
    for required in [
        "br show asupersync-idea-wizard-fifth-wave-3gaiun --json",
        "br show asupersync-idea-wizard-fifth-wave-3gaiun.16 --json",
        "br show asupersync-idea-wizard-fifth-wave-3gaiun.{1..15} --json",
    ] {
        assert!(
            commands.contains(required),
            "missing inventory command {required}"
        );
    }
    assert!(
        commands
            .iter()
            .any(|command| command.starts_with("rg --files artifacts docs tests")),
        "inventory must include checked repo-surface discovery"
    );

    let policy = string_set(inventory, "fail_closed_policy");
    for required in [
        "missing owner bead blocks closeout",
        "multiple conflicting owner beads block closeout",
        "closed owner without proof or evidence references blocks closeout",
        "open or in-progress owner without current blocker and next step blocks closeout",
        "broad readiness claim without a manifest, status, or scoped artifact reference blocks closeout",
    ] {
        assert!(policy.contains(required), "missing policy {required}");
    }
}

#[test]
fn decisions_cover_exact_top_five_next_ten_and_live_evidence() {
    let artifact = artifact();
    assert_eq!(array(&artifact, "top_five_decisions").len(), 5);
    assert_eq!(array(&artifact, "next_ten_decisions").len(), 10);

    let allowed_decisions = array(&artifact, "decision_status_catalog")
        .iter()
        .map(|row| string(row, "decision").to_owned())
        .collect::<BTreeSet<_>>();
    let mut owner_ids = BTreeSet::new();
    let mut idea_ids = BTreeSet::new();

    for row in all_decisions(&artifact) {
        let idea_id = string(row, "idea_id");
        assert!(idea_ids.insert(idea_id.to_owned()), "duplicate {idea_id}");

        let owner = string(row, "owner_bead_id");
        assert!(
            owner.starts_with(PARENT_BEAD_ID),
            "{owner} must be fifth-wave owner"
        );
        assert!(
            owner_ids.insert(owner.to_owned()),
            "duplicate owner {owner}"
        );

        let decision = string(row, "decision");
        assert!(
            allowed_decisions.contains(decision),
            "unknown decision {decision}"
        );

        let proof_refs = array(row, "proof_refs");
        let evidence_refs = array(row, "evidence_refs");
        assert!(!proof_refs.is_empty(), "{idea_id} missing proof refs");
        assert!(!evidence_refs.is_empty(), "{idea_id} missing evidence refs");
        for path in proof_refs.iter().chain(evidence_refs) {
            assert_live_path(path.as_str().expect("evidence path string"));
        }

        let status = string(row, "tracker_status");
        if status == "closed" {
            assert_eq!(
                decision, "implemented",
                "closed owner {owner} must be implemented"
            );
        } else {
            assert_eq!(
                decision, "still-open",
                "open owner {owner} must fail closed"
            );
            assert!(
                row.get("current_blocker")
                    .and_then(Value::as_str)
                    .is_some_and(|text| !text.trim().is_empty()),
                "{owner} missing blocker"
            );
            assert!(
                row.get("next_step")
                    .and_then(Value::as_str)
                    .is_some_and(|text| !text.trim().is_empty()),
                "{owner} missing next step"
            );
        }

        assert!(
            !array(row, "no_claims").is_empty(),
            "{owner} missing no-claim boundaries"
        );
    }
}

#[test]
fn closeout_verdict_names_current_blockers() {
    let artifact = artifact();
    let verdict = object(&artifact, "closeout_verdict");
    assert_eq!(
        verdict.get("status").and_then(Value::as_str),
        Some("ready_to_close")
    );
    assert!(!bool_field(verdict, "cannot_close_epic"));

    let blocker_ids = array(&artifact, "blocking_children")
        .iter()
        .map(|row| string(row, "owner_bead_id").to_owned())
        .collect::<BTreeSet<_>>();
    assert!(
        blocker_ids.is_empty(),
        "no owner rows should block closeout"
    );

    let open_owner_ids = all_decisions(&artifact)
        .into_iter()
        .filter(|row| string(row, "tracker_status") != "closed")
        .map(|row| string(row, "owner_bead_id").to_owned())
        .collect::<BTreeSet<_>>();
    assert_eq!(
        blocker_ids, open_owner_ids,
        "blocker list must match non-closed owner rows"
    );
}

#[test]
fn appspec_status_reflects_closed_a1_to_a4_chain_and_parent() {
    let artifact = artifact();
    let appspec = decision_by_idea_id(&artifact, "top-02-appspec-service-topology");
    assert_eq!(
        string(appspec, "owner_bead_id"),
        "asupersync-idea-wizard-fifth-wave-3gaiun.2"
    );
    assert_eq!(string(appspec, "tracker_status"), "closed");
    assert_eq!(string(appspec, "decision"), "implemented");
    assert!(
        appspec.get("current_blocker").is_none(),
        "closed AppSpec owner must not retain stale blocker text"
    );
    assert!(
        appspec.get("next_step").is_none(),
        "closed AppSpec owner must not retain stale next-step text"
    );

    let proof_refs = string_set(appspec, "proof_refs");
    for required in [
        "artifacts/appspec_v1_schema.json",
        "docs/appspec_v1_compiler.md",
        "artifacts/appspec_generated_lab_fixtures_v1.json",
        "tests/appspec_v1_compiler.rs",
        "tests/appspec_v1_lab_replay.rs",
        "examples/appspec_reference_journey.rs",
        "scripts/run_appspec_reference_journey_e2e.sh",
    ] {
        assert!(
            proof_refs.contains(required),
            "AppSpec proof refs must include {required}"
        );
    }

    let evidence_refs = string_set(appspec, "evidence_refs");
    for required in [
        "src/app.rs",
        "docs/appspec_generated_lab_fixtures.md",
        "examples/appspec_reference_journey.rs",
    ] {
        assert!(
            evidence_refs.contains(required),
            "AppSpec evidence refs must include {required}"
        );
    }
}

#[test]
fn handoff_requirements_and_no_claims_are_explicit() {
    let artifact = artifact();
    let handoff = object(&artifact, "handoff_record");
    assert!(bool_field(handoff, "final_tracker_comment_required"));
    assert!(bool_field(handoff, "agent_mail_handoff_required"));
    assert_eq!(
        handoff.get("primary_recipient").and_then(Value::as_str),
        Some("DarkStream")
    );

    let must_include = string_set(handoff, "must_include");
    for required in [
        "commit hash",
        "RCH proof result or refusal",
        "remaining blocking child IDs",
        "explicit no local Cargo fallback statement",
        "whether the fifth-wave epic can close",
    ] {
        assert!(
            must_include.contains(required),
            "handoff missing {required}"
        );
    }

    let no_claims = string_set(&artifact, "no_claims");
    for required in [
        "does not prove release readiness",
        "does not prove broad workspace health",
        "does not prove runtime correctness",
        "does not independently re-prove every child owner contract",
        "does not prove live RCH fleet availability",
        "does not approve local Cargo fallback",
        "does not close the fifth-wave epic",
        "does not authorize deleting files",
    ] {
        assert!(no_claims.contains(required), "missing no-claim {required}");
    }
}
