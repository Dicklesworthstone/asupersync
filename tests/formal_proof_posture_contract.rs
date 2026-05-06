#![allow(missing_docs)]

use serde_json::Value as JsonValue;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

const CONTRACT_PATH: &str = "artifacts/formal_proof_posture_contract_v1.json";
const FORMAL_README_PATH: &str = "formal/README.md";
const INVARIANT_INVENTORY_PATH: &str = "formal/lean/coverage/invariant_status_inventory.json";
const LEAN_PATH: &str = "formal/lean/Asupersync.lean";
const README_PATH: &str = "README.md";

fn repo_path(relative: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(relative)
}

fn read_repo_file(relative: &str) -> String {
    std::fs::read_to_string(repo_path(relative))
        .unwrap_or_else(|err| panic!("read {relative}: {err}"))
}

fn json_file(relative: &str) -> JsonValue {
    serde_json::from_str(&read_repo_file(relative))
        .unwrap_or_else(|err| panic!("parse {relative}: {err}"))
}

fn contains_words(text: &str, phrase: &str) -> bool {
    text.split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .contains(phrase)
}

fn string_set(value: &JsonValue, key: &str) -> BTreeSet<String> {
    value
        .get(key)
        .and_then(JsonValue::as_array)
        .unwrap_or_else(|| panic!("{key} must be an array"))
        .iter()
        .map(|entry| {
            entry
                .as_str()
                .unwrap_or_else(|| panic!("{key} entries must be strings"))
                .to_string()
        })
        .collect()
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

fn row_string_set(value: &JsonValue, key: &str) -> BTreeSet<String> {
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

fn path_is_live_or_dynamic(relative: &str) -> bool {
    relative.starts_with("target/") || repo_path(relative).exists()
}

fn invariant_ids(inventory: &JsonValue) -> BTreeSet<String> {
    inventory
        .get("invariants")
        .and_then(JsonValue::as_array)
        .expect("invariants must be an array")
        .iter()
        .map(|entry| {
            entry
                .get("id")
                .and_then(JsonValue::as_str)
                .expect("invariant id must be a string")
                .to_string()
        })
        .collect()
}

#[test]
fn contract_matches_live_invariant_inventory_summary() {
    let contract = json_file(CONTRACT_PATH);
    let inventory = json_file(INVARIANT_INVENTORY_PATH);

    assert_eq!(
        contract.get("contract_version").and_then(JsonValue::as_str),
        Some("formal-proof-posture-contract-v1")
    );
    assert_eq!(
        contract.get("bead_id").and_then(JsonValue::as_str),
        Some("asupersync-rckfrm")
    );

    let canonical = contract
        .get("canonical_inventory")
        .expect("canonical_inventory object");
    assert_eq!(
        canonical.get("path").and_then(JsonValue::as_str),
        Some(INVARIANT_INVENTORY_PATH)
    );
    assert_eq!(
        inventory.get("inventory_id").and_then(JsonValue::as_str),
        Some("lean.invariant_status.v1")
    );

    let expected = canonical
        .get("expected_summary")
        .expect("expected_summary object");
    let summary = inventory.get("summary").expect("summary object");
    for (key, value) in [
        ("fully_proven", 6),
        ("partially_proven", 0),
        ("unproven", 0),
    ] {
        assert_eq!(
            expected.get(key).and_then(JsonValue::as_u64),
            Some(value),
            "contract expected_summary.{key}"
        );
        assert_eq!(
            summary.get(key).and_then(JsonValue::as_u64),
            Some(value),
            "live inventory summary.{key}"
        );
    }

    assert_eq!(
        string_set(canonical, "required_invariant_ids"),
        invariant_ids(&inventory)
    );
}

#[test]
fn each_non_negotiable_invariant_is_fully_proven_and_linked() {
    let inventory = json_file(INVARIANT_INVENTORY_PATH);
    let invariants = inventory
        .get("invariants")
        .and_then(JsonValue::as_array)
        .expect("invariants must be an array");
    assert_eq!(
        invariants.len(),
        6,
        "expected six non-negotiable invariants"
    );

    for invariant in invariants {
        let id = invariant
            .get("id")
            .and_then(JsonValue::as_str)
            .expect("invariant id");
        assert_eq!(
            invariant.get("lean_status").and_then(JsonValue::as_str),
            Some("fully_proven"),
            "{id} must stay fully_proven"
        );
        assert!(
            invariant
                .get("lean_theorems")
                .and_then(JsonValue::as_array)
                .is_some_and(|theorems| !theorems.is_empty()),
            "{id} must name Lean theorem witnesses"
        );
        assert!(
            invariant
                .get("test_refs")
                .and_then(JsonValue::as_array)
                .is_some_and(|tests| !tests.is_empty()),
            "{id} must name executable test witnesses"
        );
        assert!(
            invariant
                .get("gaps")
                .and_then(JsonValue::as_array)
                .is_some_and(|gaps| gaps.is_empty()),
            "{id} must not carry open gaps while advertised as fully_proven"
        );
    }
}

#[test]
fn proof_tiers_keep_scope_limits_explicit() {
    let contract = json_file(CONTRACT_PATH);
    let verification = contract
        .get("toolchain_verification")
        .expect("toolchain_verification object");
    let command = verification
        .get("command")
        .and_then(JsonValue::as_str)
        .expect("verification command string");
    assert_eq!(
        command,
        "rch exec -- bash -lc 'cd formal/lean && lake build'"
    );
    assert_eq!(
        verification.get("result").and_then(JsonValue::as_str),
        Some("passed")
    );

    let scope = contract.get("scope_limits").expect("scope_limits object");
    assert_eq!(
        scope
            .get("full_runtime_proof_claimed")
            .and_then(JsonValue::as_bool),
        Some(false)
    );
    assert_eq!(
        scope
            .get("adapter_protocol_proof_claimed")
            .and_then(JsonValue::as_bool),
        Some(false)
    );
    assert_eq!(
        scope
            .get("core_invariants_fully_proven")
            .and_then(JsonValue::as_bool),
        Some(true)
    );

    let tiers = contract
        .get("proof_tiers")
        .and_then(JsonValue::as_array)
        .expect("proof_tiers array");
    let tier_names = tiers
        .iter()
        .map(|tier| {
            tier.get("tier")
                .and_then(JsonValue::as_str)
                .expect("tier string")
        })
        .collect::<BTreeSet<_>>();
    for required in [
        "semantics_source",
        "tla_model_checking",
        "lean_checked_core_invariants",
        "runtime_refinement",
        "adapter_protocol_surfaces",
    ] {
        assert!(
            tier_names.contains(required),
            "missing proof tier {required}"
        );
    }
}

#[test]
fn wave2_refinement_contract_keeps_adapter_claims_lane_specific() {
    let contract = json_file(CONTRACT_PATH);
    let scope = contract.get("scope_limits").expect("scope_limits object");
    assert_eq!(
        scope
            .get("adapter_protocol_proof_claimed")
            .and_then(JsonValue::as_bool),
        Some(false),
        "existing formal posture must not become a blanket adapter/protocol proof"
    );

    let refinement = contract
        .get("wave2_adapter_protocol_refinement")
        .expect("wave2_adapter_protocol_refinement object");
    assert_eq!(
        refinement.get("bead_id").and_then(JsonValue::as_str),
        Some("asupersync-i6uzso")
    );

    let policy = refinement.get("claim_policy").expect("claim_policy object");
    assert_eq!(
        policy
            .get("blanket_adapter_protocol_proof_claimed")
            .and_then(JsonValue::as_bool),
        Some(false)
    );
    for key in [
        "lane_specific_evidence_required",
        "missing_evidence_must_be_dispositioned",
        "assumptions_must_remain_visible",
    ] {
        assert_eq!(
            policy.get(key).and_then(JsonValue::as_bool),
            Some(true),
            "claim_policy.{key} must stay enabled"
        );
    }

    let allowed_tiers = string_set(refinement, "allowed_proof_tiers");
    for required in [
        "lean_checked",
        "tla_checked",
        "lab_oracle_backed",
        "artifact_contract_backed",
        "assumption_bound",
        "unproved_deferred",
    ] {
        assert!(
            allowed_tiers.contains(required),
            "missing allowed wave2 proof tier {required}"
        );
    }

    let required_fields = string_set(refinement, "required_lane_fields");
    for required in [
        "lane_id",
        "owner_bead_id",
        "invariant_ids",
        "proof_tier",
        "theorem_or_model_names",
        "source_paths",
        "runtime_tests",
        "e2e_artifacts",
        "assumptions",
        "missing_evidence_disposition",
        "claim_scope",
    ] {
        assert!(
            required_fields.contains(required),
            "missing required lane field {required}"
        );
    }
}

#[test]
fn wave2_refinement_lanes_link_to_live_evidence_and_visible_assumptions() {
    let contract = json_file(CONTRACT_PATH);
    let refinement = contract
        .get("wave2_adapter_protocol_refinement")
        .expect("wave2_adapter_protocol_refinement object");
    let allowed_tiers = string_set(refinement, "allowed_proof_tiers");
    let required_fields = string_set(refinement, "required_lane_fields");
    let lanes = array(refinement, "selected_lanes");
    assert!(
        lanes.len() >= 6,
        "wave2 refinement coverage must include multiple adapter/protocol lanes"
    );

    let lane_ids = lanes
        .iter()
        .map(|lane| nonempty_string(lane, "lane_id").to_string())
        .collect::<BTreeSet<_>>();
    for required in [
        "core_runtime_invariants",
        "remote_transport_lifecycle",
        "http3_qpack_instruction_streams",
        "browser_runtime_support_boundaries",
        "web_fs_messaging_adapters",
        "massive_swarm_capacity",
    ] {
        assert!(
            lane_ids.contains(required),
            "missing selected wave2 lane {required}"
        );
    }

    for lane in lanes {
        let lane_id = nonempty_string(lane, "lane_id");
        for field in &required_fields {
            assert!(
                lane.get(field).is_some(),
                "{lane_id}: missing required field {field}"
            );
        }

        let proof_tier = nonempty_string(lane, "proof_tier");
        assert!(
            allowed_tiers.contains(proof_tier),
            "{lane_id}: unsupported proof tier {proof_tier}"
        );
        assert!(
            !row_string_set(lane, "invariant_ids").is_empty(),
            "{lane_id}: invariant_ids must not be empty"
        );
        assert!(
            !row_string_set(lane, "theorem_or_model_names").is_empty(),
            "{lane_id}: theorem_or_model_names must not be empty"
        );
        assert!(
            !array(lane, "assumptions").is_empty(),
            "{lane_id}: assumptions must remain visible"
        );
        assert!(
            !nonempty_string(lane, "missing_evidence_disposition")
                .trim()
                .is_empty(),
            "{lane_id}: missing_evidence_disposition must be explicit"
        );
        let claim_scope = nonempty_string(lane, "claim_scope");
        assert!(
            !claim_scope.contains("blanket mechanized proof")
                && !claim_scope.contains("full runtime proof"),
            "{lane_id}: claim_scope must not advertise blanket mechanized proof"
        );

        for key in ["source_paths", "runtime_tests", "e2e_artifacts"] {
            let paths = array(lane, key);
            assert!(!paths.is_empty(), "{lane_id}: {key} must not be empty");
            for path in paths {
                let path = path.as_str().expect("path entries must be strings");
                assert!(
                    path_is_live_or_dynamic(path),
                    "{lane_id}: {key} entry does not resolve: {path}"
                );
            }
        }
    }
}

#[test]
fn markers_are_absent_or_inventoried_with_explicit_boundaries() {
    let contract = json_file(CONTRACT_PATH);
    let lean = read_repo_file(LEAN_PATH);
    for forbidden in ["sorry", "admit", "axiom"] {
        assert!(
            !lean.contains(forbidden),
            "Lean proof file must not contain `{forbidden}`"
        );
    }
    assert_eq!(
        lean.matches("opaque IsReady").count(),
        1,
        "the readiness model boundary should stay singular and auditable"
    );

    let markers = contract
        .get("marker_inventory")
        .and_then(JsonValue::as_array)
        .expect("marker_inventory array");
    let marker_names = markers
        .iter()
        .map(|marker| {
            marker
                .get("marker")
                .and_then(JsonValue::as_str)
                .expect("marker name string")
        })
        .collect::<BTreeSet<_>>();
    for required in [
        "sorry",
        "admit",
        "axiom",
        "opaque IsReady",
        "assumption catalog",
        "historical skeleton/scaffold wording",
    ] {
        assert!(
            marker_names.contains(required),
            "contract must inventory marker `{required}`"
        );
    }
}

#[test]
fn docs_describe_checked_core_invariants_without_stale_scaffold_claims() {
    let readme = read_repo_file(README_PATH);
    let formal_readme = read_repo_file(FORMAL_README_PATH);

    for required in [
        "Lean-checked core invariants",
        "not a blanket mechanized proof",
        "artifacts/formal_proof_posture_contract_v1.json",
        "tests/formal_proof_posture_contract.rs",
    ] {
        assert!(
            contains_words(&readme, required),
            "README missing `{required}`"
        );
        assert!(
            contains_words(&formal_readme, required),
            "formal README missing `{required}`"
        );
    }
    for required in [
        "rch exec -- bash -lc 'cd formal/lean && lake build'",
        "all six Asupersync non-negotiable invariants as `fully_proven`",
    ] {
        assert!(
            contains_words(&formal_readme, required),
            "formal README missing `{required}`"
        );
    }

    for stale in [
        "Formal Semantics (and a Lean Skeleton)",
        "Lean mechanization remains scaffold/in progress",
        "Lean scaffold lives in",
        "intentionally minimal at first",
        "Labels + step relation placeholders",
    ] {
        assert!(!readme.contains(stale), "README kept stale claim `{stale}`");
        assert!(
            !formal_readme.contains(stale),
            "formal README kept stale claim `{stale}`"
        );
    }
}
