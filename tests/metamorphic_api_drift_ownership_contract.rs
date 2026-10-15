#![allow(missing_docs)]

use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

const CONTRACT_PATH: &str = "artifacts/metamorphic_api_drift_ownership_contract_v1.json";
const EXPECTED_SCHEMA: &str = "metamorphic-api-drift-ownership-contract-v1";
const EXPECTED_BEAD: &str = "asupersync-9u057b.10";
const EXPECTED_PARENT: &str = "asupersync-9u057b";
const EXPECTED_UMBRELLA: &str = "asupersync-9u057b.8";
const REQUIRED_PROOF_PREFIX: &str =
    "rch exec -- env CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_p7 cargo";

fn repo_path(relative: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(relative)
}

fn read_repo_file(relative: &str) -> String {
    std::fs::read_to_string(repo_path(relative))
        .unwrap_or_else(|err| panic!("read {relative}: {err}"))
}

fn contract() -> Value {
    serde_json::from_str(&read_repo_file(CONTRACT_PATH))
        .unwrap_or_else(|err| panic!("parse {CONTRACT_PATH}: {err}"))
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

fn string_vec(value: &Value, key: &str) -> Vec<String> {
    array(value, key)
        .iter()
        .map(|item| {
            item.as_str()
                .unwrap_or_else(|| panic!("{key} entries must be strings"))
                .to_string()
        })
        .collect()
}

fn string_set(value: &Value, key: &str) -> BTreeSet<String> {
    string_vec(value, key).into_iter().collect()
}

#[test]
fn contract_identity_and_claim_protocol_are_pinned() {
    let contract = contract();

    assert_eq!(string(&contract, "contract_version"), EXPECTED_SCHEMA);
    assert_eq!(string(&contract, "bead_id"), EXPECTED_BEAD);
    assert_eq!(string(&contract, "parent_bead_id"), EXPECTED_PARENT);
    assert_eq!(string(&contract, "umbrella_bead_id"), EXPECTED_UMBRELLA);

    let source = object(&contract, "source_of_truth");
    assert_eq!(
        string(&Value::Object(source.clone()), "artifact"),
        CONTRACT_PATH
    );
    assert_eq!(
        string(&Value::Object(source.clone()), "contract_test"),
        "tests/metamorphic_api_drift_ownership_contract.rs"
    );

    let protocol = Value::Object(object(&contract, "claim_protocol").clone());
    assert!(bool_field(&protocol, "claim_one_surface_at_a_time"));
    assert!(bool_field(&protocol, "reserve_exact_paths_before_edit"));
    assert!(bool_field(&protocol, "do_not_claim_peer_owned_parent"));
    assert!(bool_field(&protocol, "close_child_sub_batches_separately"));

    let proof_command = string(&protocol, "cargo_proof_command");
    assert!(
        proof_command.starts_with(REQUIRED_PROOF_PREFIX),
        "proof command must use required rch target prefix: {proof_command}"
    );
    assert!(
        proof_command.contains("--test metamorphic_api_drift_ownership_contract"),
        "proof command must exercise this contract test"
    );
}

#[test]
fn repeated_failure_patterns_have_executable_examples() {
    let contract = contract();
    let required = string_set(&contract, "required_failure_pattern_ids");
    let mut seen = BTreeSet::new();

    for pattern in array(&contract, "failure_patterns") {
        let pattern_id = string(pattern, "pattern_id");
        assert!(
            seen.insert(pattern_id.to_string()),
            "duplicate {pattern_id}"
        );
        assert!(!string(pattern, "description").is_empty());
        assert!(!string(pattern, "modernization_rule").is_empty());

        let forbidden_markers = string_vec(pattern, "forbidden_markers");
        let allowed_markers = string_vec(pattern, "allowed_markers");
        let rejected_example = string(pattern, "rejected_example");
        let allowed_example = string(pattern, "allowed_example");

        assert!(
            forbidden_markers
                .iter()
                .any(|marker| rejected_example.contains(marker)),
            "{pattern_id} rejected example must contain a forbidden marker"
        );
        assert!(
            forbidden_markers
                .iter()
                .all(|marker| !allowed_example.contains(marker)),
            "{pattern_id} allowed example must avoid forbidden markers"
        );
        for marker in allowed_markers {
            assert!(
                allowed_example.contains(&marker),
                "{pattern_id} allowed example missing marker {marker:?}"
            );
        }
    }

    assert_eq!(
        seen, required,
        "failure pattern set must match required_failure_pattern_ids"
    );
}

#[test]
fn ownership_surfaces_are_unique_live_and_pattern_backed() {
    let contract = contract();
    let patterns = string_set(&contract, "required_failure_pattern_ids");
    let mut surface_ids = BTreeSet::new();
    let mut referenced_patterns = BTreeSet::new();
    let mut status_counts: BTreeMap<String, usize> = BTreeMap::new();

    for surface in array(&contract, "ownership_surfaces") {
        let surface_id = string(surface, "surface_id");
        assert!(
            surface_ids.insert(surface_id.to_string()),
            "duplicate {surface_id}"
        );

        let owner_surface = string(surface, "owner_surface");
        assert!(
            owner_surface.contains('-'),
            "{surface_id} owner surface should be file-group specific"
        );

        let status = string(surface, "claim_status");
        assert!(
            matches!(status, "modernized" | "claimable" | "blocked_external"),
            "{surface_id} has invalid claim_status {status}"
        );
        *status_counts.entry(status.to_string()).or_default() += 1;

        for path in string_vec(surface, "paths") {
            assert!(
                repo_path(&path).is_file(),
                "{surface_id} path must exist: {path}"
            );

            let contents = read_repo_file(&path);
            for marker in string_vec(surface, "evidence_markers") {
                assert!(
                    contents.contains(&marker),
                    "{surface_id} marker {marker:?} missing from {path}"
                );
            }
        }

        for pattern_id in string_vec(surface, "failure_pattern_ids") {
            assert!(
                patterns.contains(&pattern_id),
                "{surface_id} references unknown pattern {pattern_id}"
            );
            referenced_patterns.insert(pattern_id);
        }

        assert!(
            !string(surface, "next_batch_rule").is_empty(),
            "{surface_id} must explain the next claimable batch rule"
        );
    }

    assert!(
        status_counts.get("modernized").copied().unwrap_or_default() >= 2,
        "contract must retain at least two already-modernized exemplar rows"
    );
    assert!(
        status_counts.get("claimable").copied().unwrap_or_default() >= 1,
        "contract must expose at least one claimable next batch"
    );
    assert_eq!(
        referenced_patterns, patterns,
        "each required failure pattern must be assigned to at least one surface"
    );
}

#[test]
fn known_modernized_rows_preserve_their_guard_markers() {
    let contract = contract();

    for surface in array(&contract, "ownership_surfaces") {
        if string(surface, "claim_status") != "modernized" {
            continue;
        }

        let surface_id = string(surface, "surface_id");
        let markers = string_vec(surface, "evidence_markers");
        assert!(
            markers.len() >= 2,
            "{surface_id} needs both explanatory and executable markers"
        );

        let combined = string_vec(surface, "paths")
            .into_iter()
            .map(|path| read_repo_file(&path))
            .collect::<Vec<_>>()
            .join("\n");
        for marker in markers {
            assert!(
                combined.contains(&marker),
                "{surface_id} lost modernization marker {marker:?}"
            );
        }
    }
}
