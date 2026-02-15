//! Lean CI verification profile consistency checks (bd-rook4).

use serde_json::Value;
use std::collections::BTreeSet;
use std::path::PathBuf;

const PROFILES_JSON: &str = include_str!("../formal/lean/coverage/ci_verification_profiles.json");
const CI_WORKFLOW_YML: &str = include_str!("../.github/workflows/ci.yml");

fn load_beads_jsonl() -> Option<String> {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let path = manifest_dir.join(".beads/issues.jsonl");
    std::fs::read_to_string(path).ok()
}

fn known_bead_ids() -> Option<BTreeSet<String>> {
    let beads_jsonl = load_beads_jsonl()?;
    Some(
        beads_jsonl
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
            }),
    )
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
#[allow(clippy::too_many_lines)]
fn ci_artifact_contract_schema_and_retention_policy_are_explicit() {
    let profiles: Value = serde_json::from_str(PROFILES_JSON).expect("profiles json must parse");
    let artifact_contract = profiles
        .get("artifact_contract")
        .and_then(Value::as_object)
        .expect("artifact_contract must be an object");

    assert_eq!(
        artifact_contract
            .get("policy_id")
            .and_then(Value::as_str)
            .expect("artifact_contract.policy_id must be string"),
        "lean.ci.artifact_contract.v1"
    );
    assert_eq!(
        artifact_contract
            .get("manifest_schema_version")
            .and_then(Value::as_str)
            .expect("artifact_contract.manifest_schema_version must be string"),
        "lean.full.repro.bundle.v1"
    );

    let required_manifest_fields = artifact_contract
        .get("manifest_required_fields")
        .and_then(Value::as_array)
        .expect("artifact_contract.manifest_required_fields must be array")
        .iter()
        .map(|value| {
            value
                .as_str()
                .expect("artifact_contract.manifest_required_fields entries must be strings")
        })
        .collect::<BTreeSet<_>>();
    for required in [
        "schema_version",
        "generated_at_utc",
        "profile",
        "status",
        "profile_source",
        "repro_script",
        "ci_context",
        "ownership",
        "comparison_keys",
        "expected_runtime_seconds",
        "commands",
        "artifacts",
    ] {
        assert!(
            required_manifest_fields.contains(required),
            "artifact_contract.manifest_required_fields must include {required}"
        );
    }

    let retention_policy = artifact_contract
        .get("retention_policy")
        .and_then(Value::as_object)
        .expect("artifact_contract.retention_policy must be object");
    let minimum_days = retention_policy
        .get("minimum_days")
        .and_then(Value::as_u64)
        .expect("artifact_contract.retention_policy.minimum_days must be numeric");
    let default_days = retention_policy
        .get("default_days")
        .and_then(Value::as_u64)
        .expect("artifact_contract.retention_policy.default_days must be numeric");
    let maximum_days = retention_policy
        .get("maximum_days")
        .and_then(Value::as_u64)
        .expect("artifact_contract.retention_policy.maximum_days must be numeric");
    assert!(
        minimum_days <= default_days && default_days <= maximum_days,
        "retention policy must satisfy minimum_days <= default_days <= maximum_days"
    );
    assert!(
        minimum_days >= 7,
        "minimum_days should preserve at least one week of forensic reproducibility"
    );

    let misroute_tracking = artifact_contract
        .get("misroute_tracking")
        .and_then(Value::as_object)
        .expect("artifact_contract.misroute_tracking must be object");
    let misroute_policy_id = misroute_tracking
        .get("policy_id")
        .and_then(Value::as_str)
        .expect("artifact_contract.misroute_tracking.policy_id must be string");
    assert!(
        !misroute_policy_id.trim().is_empty(),
        "misroute policy_id must be non-empty"
    );
    let feedback_log_path = misroute_tracking
        .get("feedback_log_path")
        .and_then(Value::as_str)
        .expect("artifact_contract.misroute_tracking.feedback_log_path must be string");
    assert!(
        std::path::Path::new(feedback_log_path)
            .extension()
            .is_some_and(|ext| ext.eq_ignore_ascii_case("jsonl")),
        "misroute feedback log path must be jsonl for append-only auditability"
    );
    let review_window_days = misroute_tracking
        .get("review_window_days")
        .and_then(Value::as_u64)
        .expect("artifact_contract.misroute_tracking.review_window_days must be numeric");
    assert!(
        review_window_days >= 7,
        "misroute review window must be at least one week"
    );
    let max_allowed_misroutes_per_20_failures = misroute_tracking
        .get("max_allowed_misroutes_per_20_failures")
        .and_then(Value::as_u64)
        .expect(
            "artifact_contract.misroute_tracking.max_allowed_misroutes_per_20_failures must be numeric"
        );
    assert!(
        max_allowed_misroutes_per_20_failures <= 3,
        "misroute threshold should remain strict (<= 3 per 20 failures)"
    );

    let entries = profiles
        .get("profiles")
        .and_then(Value::as_array)
        .expect("profiles must be an array");
    for entry in entries {
        let name = entry
            .get("name")
            .and_then(Value::as_str)
            .expect("profile name must be string");

        let triage = entry
            .get("triage")
            .and_then(Value::as_object)
            .expect("profile triage must be object");
        let routing_policy = triage
            .get("routing_policy")
            .and_then(Value::as_str)
            .expect("triage.routing_policy must be string");
        assert!(
            !routing_policy.trim().is_empty(),
            "triage.routing_policy must be non-empty for profile {name}"
        );
        let ttfr_target_minutes = triage
            .get("ttfr_target_minutes")
            .and_then(Value::as_u64)
            .expect("triage.ttfr_target_minutes must be numeric");
        assert!(
            ttfr_target_minutes > 0,
            "triage.ttfr_target_minutes must be positive for profile {name}"
        );

        let artifact_bundle = entry
            .get("artifact_bundle")
            .and_then(Value::as_object)
            .expect("profile artifact_bundle must be object");
        let artifact_name = artifact_bundle
            .get("name")
            .and_then(Value::as_str)
            .expect("artifact_bundle.name must be string");
        assert!(
            artifact_name.starts_with("lean-"),
            "artifact_bundle.name must be prefixed with `lean-` for profile {name}"
        );
        let directory = artifact_bundle
            .get("directory")
            .and_then(Value::as_str)
            .expect("artifact_bundle.directory must be string");
        assert!(
            directory.starts_with("lean-"),
            "artifact_bundle.directory must be prefixed with `lean-` for profile {name}"
        );
        let retention_days = artifact_bundle
            .get("retention_days")
            .and_then(Value::as_u64)
            .expect("artifact_bundle.retention_days must be numeric");
        assert!(
            retention_days >= minimum_days && retention_days <= maximum_days,
            "artifact_bundle.retention_days for {name} must be within retention policy bounds"
        );
        assert!(
            artifact_bundle
                .get("failure_payload")
                .and_then(Value::as_str)
                .is_some(),
            "artifact_bundle.failure_payload must exist for profile {name}"
        );
    }

    let full = entries
        .iter()
        .find(|entry| entry.get("name").and_then(Value::as_str) == Some("full"))
        .expect("full profile must exist");
    let full_bundle = full
        .get("artifact_bundle")
        .and_then(Value::as_object)
        .expect("full profile artifact_bundle must be object");
    for field in ["repro_bundle_manifest", "repro_script", "failure_payload"] {
        assert!(
            full_bundle.get(field).and_then(Value::as_str).is_some(),
            "full artifact bundle must include {field}"
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

    let Some(bead_ids) = known_bead_ids() else {
        return;
    };

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
#[allow(clippy::too_many_lines)]
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

    let Some(bead_ids) = known_bead_ids() else {
        return;
    };
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

#[test]
#[allow(clippy::too_many_lines)]
fn ci_governance_policy_defines_cadence_and_decision_record_contract() {
    let profiles: Value = serde_json::from_str(PROFILES_JSON).expect("profiles json must parse");
    let governance_policy = profiles
        .get("governance_policy")
        .and_then(Value::as_object)
        .expect("governance_policy must be an object");

    assert_eq!(
        governance_policy
            .get("policy_id")
            .and_then(Value::as_str)
            .expect("governance_policy.policy_id must be a string"),
        "lean.ci.governance.cadence.v1"
    );
    let decision_log_path = governance_policy
        .get("decision_log_path")
        .and_then(Value::as_str)
        .expect("governance_policy.decision_log_path must be a string");
    assert!(
        std::path::Path::new(decision_log_path)
            .extension()
            .is_some_and(|ext| ext.eq_ignore_ascii_case("jsonl")),
        "governance decision log path must be jsonl for append-only governance history"
    );

    let reviews = governance_policy
        .get("reviews")
        .and_then(Value::as_array)
        .expect("governance_policy.reviews must be an array");
    assert!(
        reviews.len() >= 2,
        "governance_policy.reviews must include weekly and phase-exit reviews"
    );

    let mut review_ids = BTreeSet::new();
    for review in reviews {
        let review_id = review
            .get("review_id")
            .and_then(Value::as_str)
            .expect("governance review_id must be a string");
        assert!(
            review_ids.insert(review_id.to_string()),
            "duplicate governance review_id: {review_id}"
        );

        let cadence = review
            .get("cadence")
            .and_then(Value::as_str)
            .expect("governance cadence must be a string");
        assert!(
            matches!(cadence, "weekly" | "phase-exit"),
            "governance cadence must be weekly or phase-exit"
        );

        let participants = review
            .get("required_participants")
            .and_then(Value::as_array)
            .expect("required_participants must be an array");
        assert!(
            !participants.is_empty(),
            "required_participants must be non-empty"
        );
        for participant in participants {
            let role = participant
                .as_str()
                .expect("required_participants entries must be strings");
            assert!(
                !role.trim().is_empty(),
                "participant role must be non-empty"
            );
        }

        let artifacts = review
            .get("required_artifacts")
            .and_then(Value::as_array)
            .expect("required_artifacts must be an array");
        assert!(
            !artifacts.is_empty(),
            "required_artifacts must be non-empty"
        );
        for artifact in artifacts {
            let path = artifact
                .as_str()
                .expect("required_artifacts entries must be strings");
            assert!(
                path.starts_with("formal/lean/coverage/"),
                "governance required_artifacts must reference canonical coverage artifacts"
            );
        }

        for rule_field in ["bead_status_update_rule", "dependency_update_rule"] {
            let rule = review
                .get(rule_field)
                .and_then(Value::as_str)
                .expect("governance review rule fields must be strings");
            assert!(!rule.trim().is_empty(), "{rule_field} must be non-empty");
        }
    }
    for required_review in ["weekly-proof-health", "phase-exit-signoff"] {
        assert!(
            review_ids.contains(required_review),
            "governance reviews must include {required_review}"
        );
    }

    let template = governance_policy
        .get("decision_record_template")
        .and_then(Value::as_object)
        .expect("decision_record_template must be an object");
    let required_fields = template
        .get("required_fields")
        .and_then(Value::as_array)
        .expect("decision_record_template.required_fields must be an array")
        .iter()
        .map(|value| {
            value
                .as_str()
                .expect("required_fields entries must be strings")
        })
        .collect::<BTreeSet<_>>();
    for required in [
        "decision_id",
        "review_id",
        "taken_at_utc",
        "participants",
        "summary",
        "rationale",
        "linked_bead_ids",
        "linked_artifact_paths",
        "temporary",
        "expires_at_utc",
        "bead_status_changes",
        "dependency_changes",
    ] {
        assert!(
            required_fields.contains(required),
            "decision_record_template.required_fields must include {required}"
        );
    }

    let temporary_requires_expiry = template
        .get("temporary_decisions_require_expiry")
        .and_then(Value::as_bool)
        .expect("temporary_decisions_require_expiry must be boolean");
    assert!(
        temporary_requires_expiry,
        "temporary decision records must require an expiry field"
    );

    let bead_status_change_required_fields = template
        .get("bead_status_change_required_fields")
        .and_then(Value::as_array)
        .expect("bead_status_change_required_fields must be an array")
        .iter()
        .map(|value| {
            value
                .as_str()
                .expect("bead_status_change_required_fields entries must be strings")
        })
        .collect::<BTreeSet<_>>();
    for required in ["bead_id", "from_status", "to_status", "reason"] {
        assert!(
            bead_status_change_required_fields.contains(required),
            "bead_status_change_required_fields must include {required}"
        );
    }

    let dependency_change_required_fields = template
        .get("dependency_change_required_fields")
        .and_then(Value::as_array)
        .expect("dependency_change_required_fields must be an array")
        .iter()
        .map(|value| {
            value
                .as_str()
                .expect("dependency_change_required_fields entries must be strings")
        })
        .collect::<BTreeSet<_>>();
    for required in [
        "blocked_bead_id",
        "blocking_bead_id",
        "change_type",
        "reason",
    ] {
        assert!(
            dependency_change_required_fields.contains(required),
            "dependency_change_required_fields must include {required}"
        );
    }

    let allowed_dependency_change_types = template
        .get("allowed_dependency_change_types")
        .and_then(Value::as_array)
        .expect("allowed_dependency_change_types must be an array")
        .iter()
        .map(|value| {
            value
                .as_str()
                .expect("allowed_dependency_change_types entries must be strings")
        })
        .collect::<BTreeSet<_>>();
    assert!(
        allowed_dependency_change_types.contains("add")
            && allowed_dependency_change_types.contains("remove"),
        "allowed_dependency_change_types must include add/remove"
    );
}

#[test]
fn lean_smoke_failure_payload_routes_to_owners_deterministically() {
    for required_snippet in [
        ".beads/issues.jsonl",
        "Resolve Lean smoke artifact contract",
        ".profiles[] | select(.name == \"smoke\")",
        ".triage.routing_policy",
        ".triage.ttfr_target_minutes",
        ".artifact_bundle.failure_payload",
        ".governance_policy.policy_id // empty",
        ".governance_policy.decision_log_path // empty",
        ".governance_policy.reviews[] | select(.review_id == \"weekly-proof-health\")",
        "ttfr_target_minutes",
        "misroute_tracking",
        "governance_weekly_review_json",
        "governance_decision_required_fields_json",
        "decision_record_required_fields",
        "owner_candidates",
        "routed_owners",
        "primary_owner",
        "first_action_checklist",
        "Append governance decision record",
    ] {
        assert!(
            CI_WORKFLOW_YML.contains(required_snippet),
            "ci workflow must include `{required_snippet}` in lean-smoke failure payload contract"
        );
    }
}

#[test]
fn lean_smoke_gate_is_pr_scoped_and_profile_driven() {
    for required_snippet in [
        "Lean Smoke Gate (PR)",
        "if: github.event_name == 'pull_request'",
        "select(.name == \"smoke\")",
        ".artifact_bundle.name // empty",
        ".artifact_bundle.directory // empty",
        ".artifact_bundle.retention_days // empty",
        "Run Lean smoke profile commands",
        "Upload Lean smoke artifacts",
        "steps.lean_smoke_contract.outputs.artifact_name",
        "steps.lean_smoke_contract.outputs.artifact_dir",
    ] {
        assert!(
            CI_WORKFLOW_YML.contains(required_snippet),
            "ci workflow must include `{required_snippet}` in lean-smoke gate contract"
        );
    }
}

#[test]
fn lean_full_gate_emits_repro_bundle_and_routing_contract() {
    for required_snippet in [
        "Lean Full Gate (Main/Release)",
        "Resolve Lean full artifact contract",
        ".artifact_contract.manifest_schema_version // empty",
        ".artifact_contract.misroute_tracking.policy_id // empty",
        ".governance_policy.policy_id // empty",
        ".governance_policy.decision_log_path // empty",
        ".governance_policy.reviews[] | select(.review_id == \"phase-exit-signoff\")",
        "select(.name == \"full\")",
        ".artifact_bundle.repro_bundle_manifest // empty",
        ".artifact_bundle.repro_script // empty",
        ".artifact_bundle.failure_payload // empty",
        ".triage.routing_policy",
        ".triage.ttfr_target_minutes",
        "misroute_tracking",
        "governance_phase_exit_review_json",
        "governance_decision_required_fields_json",
        "decision_record_required_fields",
        "steps.lean_full_contract.outputs.repro_bundle_manifest",
        "steps.lean_full_contract.outputs.repro_script",
        "steps.lean_full_contract.outputs.failure_payload",
        "Append governance decision record",
        "Upload Lean full artifacts",
        "steps.lean_full_contract.outputs.artifact_name",
    ] {
        assert!(
            CI_WORKFLOW_YML.contains(required_snippet),
            "ci workflow must include `{required_snippet}` in lean-full gate contract"
        );
    }
}
