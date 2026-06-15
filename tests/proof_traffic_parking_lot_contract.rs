//! Contract tests for PROOF-TRAFFIC A4 parked proof manifests.
//!
//! The parking lot is not a second tracker and not proof evidence. It preserves
//! enough context to resume a focused proof once its retry predicate is
//! satisfied, while grouping duplicate blockers for operator triage.

#![allow(missing_docs)]

use asupersync::audit::proof_traffic_parking_lot::{
    PROOF_TRAFFIC_PARKING_LOT_SCHEMA_VERSION, ParkedProofAttempt, ProofTrafficParkingLot,
    ProofTrafficRetryPredicate,
};
use asupersync::audit::proof_traffic_receipt::ProofTrafficDecision;
use serde_json::Value;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

const ARTIFACT_PATH: &str = "artifacts/proof_traffic_parking_lot_v1.json";
const DOCS_PATH: &str = "docs/proof_traffic_control.md";
const LOT_ID: &str = "asupersync-proof-traffic-control-kuyx64.4";
const HEAD: &str = "09d8a8919cafebeef000000000000000000000";
const TARGET_DIR: &str = "${TMPDIR:-/tmp}/rch_target_proof_traffic_parking_lot";
const COMMAND_A: &str = "RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_a cargo test -p asupersync --test proof_a -- --nocapture";
const COMMAND_B: &str = "RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_b cargo test -p asupersync --test proof_b -- --nocapture";

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

fn array<'a>(value: &'a Value, key: &str) -> &'a [Value] {
    value[key]
        .as_array()
        .unwrap_or_else(|| panic!("{key} array"))
        .as_slice()
}

fn string_field<'a>(value: &'a Value, key: &str) -> &'a str {
    let text = value[key]
        .as_str()
        .unwrap_or_else(|| panic!("{key} string"));
    assert!(!text.trim().is_empty(), "{key} must be nonempty");
    text
}

fn string_set(value: &Value, key: &str) -> BTreeSet<String> {
    array(value, key)
        .iter()
        .map(|entry| entry.as_str().expect("string entry").to_string())
        .collect()
}

fn predicate(id: &str, satisfied: bool) -> ProofTrafficRetryPredicate {
    ProofTrafficRetryPredicate::new(
        id,
        "remote worker accepts focused proof",
        "fresh RCH terminal output",
        satisfied,
    )
}

fn attempt(
    attempt_id: &str,
    blocker_key: &str,
    decision: ProofTrafficDecision,
    command: Option<&str>,
    satisfied: bool,
) -> ParkedProofAttempt {
    let base = ParkedProofAttempt::new(
        attempt_id,
        blocker_key,
        HEAD,
        format!("cargo test -p asupersync --test {attempt_id} -- --nocapture"),
        TARGET_DIR,
        decision,
        predicate(&format!("retry-{blocker_key}"), satisfied),
    )
    .with_paths(
        vec![format!("src/audit/{attempt_id}.rs")],
        vec![format!("src/audit/{attempt_id}.rs")],
    )
    .with_blocker_marker(format!(
        "# PARKED: blocker={blocker_key}; no proof command emitted"
    ))
    .with_handoff(Some("PeerAgent".to_string()), Some("thread-42".to_string()));

    if let Some(command) = command {
        base.with_exact_rch_command(command)
    } else {
        base
    }
}

fn parking_lot() -> ProofTrafficParkingLot {
    ProofTrafficParkingLot::new(
        LOT_ID,
        vec![
            attempt(
                "attempt-b",
                "capability-drift:rch-clean-overlay",
                ProofTrafficDecision::BlockedByCapabilityDrift,
                Some(COMMAND_B),
                false,
            ),
            attempt(
                "attempt-a",
                "capability-drift:rch-clean-overlay",
                ProofTrafficDecision::BlockedByCapabilityDrift,
                Some(COMMAND_A),
                false,
            ),
            attempt(
                "attempt-ready",
                "active-project-exclusion",
                ProofTrafficDecision::ParkRerunRequired,
                Some(COMMAND_A),
                true,
            ),
            attempt(
                "attempt-marker-only",
                "peer-stale:29887347701055977",
                ProofTrafficDecision::BlockedByPeer,
                None,
                true,
            ),
        ],
    )
}

#[test]
fn duplicate_blockers_are_grouped_without_losing_attempt_details() {
    let lot = parking_lot();
    assert_eq!(lot.schema_version, PROOF_TRAFFIC_PARKING_LOT_SCHEMA_VERSION);
    assert_eq!(
        lot.attempts
            .iter()
            .map(|attempt| attempt.attempt_id.as_str())
            .collect::<Vec<_>>(),
        vec![
            "attempt-a",
            "attempt-b",
            "attempt-marker-only",
            "attempt-ready"
        ]
    );

    let group = lot
        .groups
        .iter()
        .find(|group| group.blocker_key == "capability-drift:rch-clean-overlay")
        .expect("capability drift group");
    assert_eq!(group.attempt_count, 2);
    assert_eq!(group.attempt_ids, vec!["attempt-a", "attempt-b"]);
    assert_eq!(group.command_intents.len(), 2);
    assert!(
        group
            .owned_paths
            .contains(&"src/audit/attempt-a.rs".to_string())
    );
    assert!(
        group
            .owned_paths
            .contains(&"src/audit/attempt-b.rs".to_string())
    );
}

#[test]
fn resume_renderer_emits_exact_command_only_when_retry_predicate_is_satisfied() {
    let lot = parking_lot();

    let parked = lot.render_resume("attempt-a").expect("attempt-a");
    assert!(parked.starts_with("# PARKED"));
    assert!(!parked.contains("cargo test"));
    assert!(parked.contains("satisfied=false"));

    let ready = lot.render_resume("attempt-ready").expect("attempt-ready");
    assert_eq!(ready, COMMAND_A);
    assert!(ready.contains("RCH_REQUIRE_REMOTE=1 rch exec"));

    let marker_only = lot
        .render_resume("attempt-marker-only")
        .expect("attempt-marker-only");
    assert!(marker_only.starts_with("# PARKED"));
    assert!(!marker_only.contains("cargo test"));
    assert!(marker_only.contains("satisfied=true"));
}

#[test]
fn refused_stale_and_parked_attempts_cannot_be_cited_as_green() {
    let lot = parking_lot();
    for attempt in &lot.attempts {
        assert!(!attempt.can_be_cited_as_green());
        assert_ne!(
            attempt.blocker_class,
            ProofTrafficDecision::RunNow,
            "parking lot should not store green proof as a parked blocker"
        );
        assert!(
            attempt
                .no_claim_boundaries
                .iter()
                .any(|boundary| boundary.contains("not green proof evidence"))
        );
    }
}

#[test]
fn markdown_agent_mail_and_br_bodies_are_deterministic() {
    let lot = parking_lot();
    let markdown = lot.render_markdown();
    assert_eq!(markdown, lot.render_markdown());
    for needle in [
        "Proof-traffic parking lot",
        "schema_version",
        "attempt_count",
        "group_count",
        "capability-drift:rch-clean-overlay",
        "attempt-a,attempt-b",
        "not green proof evidence",
    ] {
        assert!(markdown.contains(needle), "markdown missing {needle}");
    }

    let agent_mail = lot.agent_mail_body();
    let br_comment = lot.br_comment_body();
    assert!(agent_mail.contains("proof_traffic_parking_lot"));
    assert!(agent_mail.contains("blocker_key"));
    assert!(br_comment.contains("Proof-traffic parking lot"));
    assert!(br_comment.contains("group_count"));
}

#[test]
fn serde_roundtrip_preserves_groups_and_resume_behavior() {
    let lot = parking_lot();
    let json = serde_json::to_string(&lot).expect("serialize lot");
    let back: ProofTrafficParkingLot = serde_json::from_str(&json).expect("deserialize lot");
    assert_eq!(back, lot);
    assert_eq!(
        back.render_resume("attempt-ready"),
        Some(COMMAND_A.to_string())
    );
    assert!(
        back.render_resume("attempt-a")
            .expect("attempt-a")
            .starts_with("# PARKED")
    );
}

#[test]
fn artifact_and_docs_pin_a4_contract_scope() {
    let artifact = json(ARTIFACT_PATH);
    assert_eq!(
        string_field(&artifact, "schema_version"),
        "proof-traffic-parking-lot-v1"
    );
    assert_eq!(string_field(&artifact, "bead_id"), LOT_ID);
    assert_eq!(string_field(&artifact, "status"), "contract_guarded");

    for path in [
        string_field(&artifact["source_of_truth"], "artifact"),
        string_field(&artifact["source_of_truth"], "operator_doc"),
        string_field(&artifact["source_of_truth"], "contract_test"),
        string_field(&artifact["source_of_truth"], "rust_module"),
    ] {
        assert!(repo_path(path).exists(), "{path} must exist");
    }

    let fields = string_set(&artifact, "required_attempt_fields");
    for field in [
        "head_commit",
        "command_intent",
        "exact_rch_command_or_blocker_marker",
        "target_dir",
        "owned_paths",
        "reservation_evidence",
        "blocker_class",
        "blocker_owner_or_thread",
        "retry_predicate",
        "no_claim_boundaries",
    ] {
        assert!(fields.contains(field), "missing field {field}");
    }

    let docs = read_repo_file(DOCS_PATH);
    for needle in [
        "Proof-Traffic A4 Parking Lot",
        "artifacts/proof_traffic_parking_lot_v1.json",
        "tests/proof_traffic_parking_lot_contract.rs",
        "retry predicate",
        "Duplicate parked attempts",
        "not green proof evidence",
    ] {
        assert!(docs.contains(needle), "docs missing {needle}");
    }
}
