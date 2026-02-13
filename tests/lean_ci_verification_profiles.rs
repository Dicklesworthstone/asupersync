//! Lean CI verification profile consistency checks (bd-rook4).

use serde_json::Value;
use std::collections::BTreeSet;

const PROFILES_JSON: &str = include_str!("../formal/lean/coverage/ci_verification_profiles.json");
const BEADS_JSONL: &str = include_str!("../.beads/issues.jsonl");

#[test]
fn ci_profiles_have_required_shape_and_ordering() {
    let profiles: Value = serde_json::from_str(PROFILES_JSON).expect("profiles json must parse");
    assert_eq!(
        profiles
            .get("schema_version")
            .and_then(Value::as_str)
            .expect("schema_version must be string"),
        "1.0.0"
    );

    let ordering = profiles
        .get("ordering")
        .and_then(Value::as_array)
        .expect("ordering must be an array")
        .iter()
        .map(|v| v.as_str().expect("ordering entries must be strings"))
        .collect::<Vec<_>>();
    assert_eq!(ordering, vec!["smoke", "frontier", "full"]);

    let entries = profiles
        .get("profiles")
        .and_then(Value::as_array)
        .expect("profiles must be an array");
    assert_eq!(entries.len(), 3, "expected exactly three CI profiles");

    let names = entries
        .iter()
        .map(|entry| {
            entry
                .get("name")
                .and_then(Value::as_str)
                .expect("profile name must be a string")
        })
        .collect::<BTreeSet<_>>();
    assert_eq!(names, BTreeSet::from(["smoke", "frontier", "full"]));

    for entry in entries {
        let entry_conditions = entry
            .get("entry_conditions")
            .and_then(Value::as_array)
            .expect("entry_conditions must be an array");
        assert!(
            !entry_conditions.is_empty(),
            "entry_conditions must not be empty"
        );

        let commands = entry
            .get("commands")
            .and_then(Value::as_array)
            .expect("commands must be an array");
        assert!(!commands.is_empty(), "commands must not be empty");

        let artifacts = entry
            .get("output_artifacts")
            .and_then(Value::as_array)
            .expect("output_artifacts must be an array");
        assert!(!artifacts.is_empty(), "output_artifacts must not be empty");

        let comparison_keys = entry
            .get("comparison_keys")
            .and_then(Value::as_array)
            .expect("comparison_keys must be an array")
            .iter()
            .map(|v| v.as_str().expect("comparison_keys must be strings"))
            .collect::<BTreeSet<_>>();
        assert!(
            comparison_keys.contains("profile_name"),
            "comparison_keys must contain profile_name"
        );
        assert!(
            comparison_keys.contains("git_commit"),
            "comparison_keys must contain git_commit"
        );
        assert!(
            comparison_keys.contains("artifact_hashes_sha256"),
            "comparison_keys must contain artifact_hashes_sha256"
        );
    }
}

#[test]
fn ci_profile_runtime_order_and_bead_links_are_valid() {
    let profiles: Value = serde_json::from_str(PROFILES_JSON).expect("profiles json must parse");
    let entries = profiles
        .get("profiles")
        .and_then(Value::as_array)
        .expect("profiles must be an array");

    let runtime_targets = entries
        .iter()
        .map(|entry| {
            let name = entry
                .get("name")
                .and_then(Value::as_str)
                .expect("profile name must be string");
            let target = entry
                .pointer("/expected_runtime_seconds/target")
                .and_then(Value::as_u64)
                .expect("target runtime must be numeric");
            let p95 = entry
                .pointer("/expected_runtime_seconds/p95")
                .and_then(Value::as_u64)
                .expect("p95 runtime must be numeric");
            let max = entry
                .pointer("/expected_runtime_seconds/max")
                .and_then(Value::as_u64)
                .expect("max runtime must be numeric");
            assert!(
                target <= p95 && p95 <= max,
                "runtime budget must satisfy target <= p95 <= max for {name}"
            );
            (name, target, p95, max)
        })
        .collect::<Vec<_>>();

    let smoke = runtime_targets
        .iter()
        .find(|(name, _, _, _)| *name == "smoke")
        .expect("smoke profile must exist");
    let frontier = runtime_targets
        .iter()
        .find(|(name, _, _, _)| *name == "frontier")
        .expect("frontier profile must exist");
    let full = runtime_targets
        .iter()
        .find(|(name, _, _, _)| *name == "full")
        .expect("full profile must exist");
    assert!(
        smoke.1 < frontier.1 && frontier.1 < full.1,
        "target runtime must be strictly increasing smoke < frontier < full"
    );

    let bead_ids = BEADS_JSONL
        .lines()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .fold(BTreeSet::new(), |mut ids, entry| {
            if let Some(id) = entry.get("id").and_then(Value::as_str) {
                ids.insert(id.to_string());
            }
            if let Some(external_ref) = entry.get("external_ref").and_then(Value::as_str) {
                ids.insert(external_ref.to_string());
            }
            ids
        });

    for entry in entries {
        let ownership = entry
            .get("ownership")
            .and_then(Value::as_object)
            .expect("ownership must be an object");
        for field in ["primary_bead", "failure_triage_bead", "escalation_bead"] {
            let bead_id = ownership
                .get(field)
                .and_then(Value::as_str)
                .expect("ownership bead reference must be string");
            assert!(
                bead_ids.contains(bead_id),
                "ownership field {field} references unknown bead {bead_id}"
            );
        }
    }
}
