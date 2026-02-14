//! Lean CI verification profile consistency checks (bd-rook4).

use serde_json::Value;
use std::collections::BTreeSet;

const PROFILES_JSON: &str = include_str!("../formal/lean/coverage/ci_verification_profiles.json");
const BEADS_JSONL: &str = include_str!("../.beads/issues.jsonl");

fn known_bead_ids() -> BTreeSet<String> {
    BEADS_JSONL
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
        })
}

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

    let bead_ids = known_bead_ids();

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

#[test]
fn ci_profile_waiver_policy_enforces_expiry_and_closure_paths() {
    let profiles: Value = serde_json::from_str(PROFILES_JSON).expect("profiles json must parse");
    let waiver_policy = profiles
        .get("waiver_policy")
        .and_then(Value::as_object)
        .expect("waiver_policy must be an object");

    let governance_reference = waiver_policy
        .get("governance_reference_time_utc")
        .and_then(Value::as_str)
        .expect("governance_reference_time_utc must be a string");
    assert!(
        governance_reference.ends_with('Z'),
        "governance_reference_time_utc must be UTC RFC3339 (Z suffix)"
    );

    let required_fields = waiver_policy
        .get("required_fields")
        .and_then(Value::as_array)
        .expect("required_fields must be an array")
        .iter()
        .map(|value| value.as_str().expect("required_fields must be strings"))
        .collect::<BTreeSet<_>>();
    for required in [
        "waiver_id",
        "owner",
        "reason",
        "risk_class",
        "expires_at_utc",
        "closure_dependency_path",
        "status",
    ] {
        assert!(
            required_fields.contains(required),
            "required_fields must include {required}"
        );
    }

    let risk_classes = waiver_policy
        .get("risk_classes")
        .and_then(Value::as_array)
        .expect("risk_classes must be an array")
        .iter()
        .map(|value| value.as_str().expect("risk_classes must be strings"))
        .collect::<BTreeSet<_>>();
    let statuses = waiver_policy
        .get("status_values")
        .and_then(Value::as_array)
        .expect("status_values must be an array")
        .iter()
        .map(|value| value.as_str().expect("status_values must be strings"))
        .collect::<BTreeSet<_>>();

    let governance_checks = waiver_policy
        .get("governance_checks")
        .and_then(Value::as_array)
        .expect("governance_checks must be an array");
    let check_ids = governance_checks
        .iter()
        .map(|entry| {
            entry
                .get("check_id")
                .and_then(Value::as_str)
                .expect("governance check_id must be string")
        })
        .collect::<BTreeSet<_>>();
    for required in [
        "waiver.expiry.enforced",
        "waiver.closure_path.required",
        "waiver.closed_requires_closure_bead",
    ] {
        assert!(
            check_ids.contains(required),
            "governance_checks must include {required}"
        );
    }

    let waivers = waiver_policy
        .get("waivers")
        .and_then(Value::as_array)
        .expect("waivers must be an array");
    assert!(!waivers.is_empty(), "waivers list must not be empty");

    let bead_ids = known_bead_ids();
    let mut waiver_ids = BTreeSet::new();
    for waiver in waivers {
        let waiver_id = waiver
            .get("waiver_id")
            .and_then(Value::as_str)
            .expect("waiver_id must be string");
        assert!(
            waiver_ids.insert(waiver_id.to_string()),
            "duplicate waiver_id: {waiver_id}"
        );

        let owner = waiver
            .get("owner")
            .and_then(Value::as_str)
            .expect("owner must be string");
        assert!(!owner.trim().is_empty(), "owner must be non-empty");

        let reason = waiver
            .get("reason")
            .and_then(Value::as_str)
            .expect("reason must be string");
        assert!(!reason.trim().is_empty(), "reason must be non-empty");

        let risk_class = waiver
            .get("risk_class")
            .and_then(Value::as_str)
            .expect("risk_class must be string");
        assert!(
            risk_classes.contains(risk_class),
            "risk_class must be from risk_classes: {risk_class}"
        );

        let status = waiver
            .get("status")
            .and_then(Value::as_str)
            .expect("status must be string");
        assert!(
            statuses.contains(status),
            "status must be from status_values: {status}"
        );

        let expires_at = waiver
            .get("expires_at_utc")
            .and_then(Value::as_str)
            .expect("expires_at_utc must be string");
        assert!(
            expires_at.ends_with('Z'),
            "expires_at_utc must be UTC RFC3339 (Z suffix)"
        );

        let closure_path = waiver
            .get("closure_dependency_path")
            .and_then(Value::as_array)
            .expect("closure_dependency_path must be an array");
        assert!(
            !closure_path.is_empty(),
            "closure_dependency_path must be non-empty for {waiver_id}"
        );
        for dependency in closure_path {
            let dep_id = dependency
                .as_str()
                .expect("closure_dependency_path entries must be strings");
            assert!(
                bead_ids.contains(dep_id),
                "closure_dependency_path references unknown bead {dep_id}"
            );
        }

        if status == "active" {
            assert!(
                expires_at > governance_reference,
                "active waiver {waiver_id} is expired at governance reference time"
            );
        } else if status == "closed" {
            let closure_bead = waiver
                .get("closure_bead")
                .and_then(Value::as_str)
                .expect("closed waiver must include closure_bead");
            assert!(
                bead_ids.contains(closure_bead),
                "closure_bead references unknown bead {closure_bead}"
            );

            let closed_at = waiver
                .get("closed_at_utc")
                .and_then(Value::as_str)
                .expect("closed waiver must include closed_at_utc");
            assert!(
                closed_at.ends_with('Z'),
                "closed_at_utc must be UTC RFC3339 (Z suffix)"
            );
        }
    }
}
