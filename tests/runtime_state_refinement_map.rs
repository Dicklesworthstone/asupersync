//! Validation for RuntimeState cross-entity refinement mapping artifact (bd-23hq7).

use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

const MAP_JSON: &str = include_str!("../formal/lean/coverage/runtime_state_refinement_map.json");
const STEP_COVERAGE_JSON: &str =
    include_str!("../formal/lean/coverage/step_constructor_coverage.json");
const THEOREM_INVENTORY_JSON: &str =
    include_str!("../formal/lean/coverage/theorem_surface_inventory.json");

fn theorem_line_lookup() -> BTreeMap<String, u64> {
    let inventory: Value =
        serde_json::from_str(THEOREM_INVENTORY_JSON).expect("theorem inventory must parse");
    inventory
        .get("theorems")
        .and_then(Value::as_array)
        .expect("theorem inventory must contain a theorem array")
        .iter()
        .map(|entry| {
            (
                entry
                    .get("theorem")
                    .and_then(Value::as_str)
                    .expect("theorem name must be a string")
                    .to_string(),
                entry
                    .get("line")
                    .and_then(Value::as_u64)
                    .expect("theorem line must be numeric"),
            )
        })
        .collect()
}

fn valid_rule_ids() -> BTreeSet<String> {
    let step_coverage: Value =
        serde_json::from_str(STEP_COVERAGE_JSON).expect("step coverage must parse");
    step_coverage
        .get("constructors")
        .and_then(Value::as_array)
        .expect("step coverage must contain constructors")
        .iter()
        .map(|entry| {
            let constructor = entry
                .get("constructor")
                .and_then(Value::as_str)
                .expect("constructor must be a string");
            format!("step.{constructor}")
        })
        .collect()
}

#[test]
fn runtime_state_refinement_map_covers_required_operations() {
    let map: Value =
        serde_json::from_str(MAP_JSON).expect("runtime state refinement map must parse");
    assert_eq!(
        map.get("schema_version")
            .and_then(Value::as_str)
            .expect("schema_version must be present"),
        "1.0.0"
    );
    assert_eq!(
        map.get("map_id")
            .and_then(Value::as_str)
            .expect("map_id must be present"),
        "lean.runtime_state_refinement_map.v1"
    );

    let mappings = map
        .get("mappings")
        .and_then(Value::as_array)
        .expect("mappings must be an array");
    assert!(!mappings.is_empty(), "mappings array must not be empty");

    let required = BTreeSet::from([
        "runtime_state.create_obligation",
        "runtime_state.commit_obligation",
        "runtime_state.abort_obligation",
        "runtime_state.mark_obligation_leaked",
        "runtime_state.cancel_request",
        "runtime_state.task_completed",
        "runtime_state.advance_region_state",
        "scheduler.three_lane.next_task",
        "scope.race_all_loser_drain",
    ]);

    let mapped_ids = mappings
        .iter()
        .map(|entry| {
            entry
                .get("operation_id")
                .and_then(Value::as_str)
                .expect("operation_id must be present")
        })
        .collect::<BTreeSet<_>>();

    for op in required {
        assert!(
            mapped_ids.contains(op),
            "required operation mapping missing: {op}"
        );
    }
}

#[test]
#[allow(clippy::too_many_lines)]
fn runtime_state_refinement_map_links_valid_rules_and_theorems() {
    let map: Value =
        serde_json::from_str(MAP_JSON).expect("runtime state refinement map must parse");
    let mappings = map
        .get("mappings")
        .and_then(Value::as_array)
        .expect("mappings must be an array");
    let rule_ids = valid_rule_ids();
    let theorem_lines = theorem_line_lookup();

    for mapping in mappings {
        let operation_id = mapping
            .get("operation_id")
            .and_then(Value::as_str)
            .expect("operation_id must be a string");

        let rust_method = mapping
            .get("rust_method")
            .expect("rust_method must be present");
        assert!(
            rust_method
                .get("name")
                .and_then(Value::as_str)
                .is_some_and(|name| !name.trim().is_empty()),
            "rust_method.name must be non-empty for {operation_id}"
        );
        assert!(
            rust_method
                .get("file_path")
                .and_then(Value::as_str)
                .is_some_and(|path| !path.trim().is_empty()),
            "rust_method.file_path must be non-empty for {operation_id}"
        );
        assert!(
            rust_method
                .get("line")
                .and_then(Value::as_u64)
                .is_some_and(|line| line > 0),
            "rust_method.line must be positive for {operation_id}"
        );

        let owner = mapping.get("owner").and_then(Value::as_str).unwrap_or("");
        assert!(
            !owner.trim().is_empty(),
            "owner must be non-empty for {operation_id}"
        );

        let update_trigger_conditions = mapping
            .get("update_trigger_conditions")
            .and_then(Value::as_array)
            .expect("update_trigger_conditions must be an array");
        assert!(
            !update_trigger_conditions.is_empty(),
            "update_trigger_conditions must be non-empty for {operation_id}"
        );
        for trigger in update_trigger_conditions {
            assert!(
                trigger
                    .as_str()
                    .is_some_and(|value| !value.trim().is_empty()),
                "update_trigger_conditions entries must be non-empty for {operation_id}"
            );
        }

        let formal_labels = mapping
            .get("formal_labels")
            .and_then(Value::as_array)
            .expect("formal_labels must be an array");
        assert!(
            !formal_labels.is_empty(),
            "formal_labels must be non-empty for {operation_id}"
        );
        let labels = formal_labels
            .iter()
            .map(|label| label.as_str().expect("formal label must be a string"))
            .collect::<Vec<_>>();
        let unique = labels.iter().copied().collect::<BTreeSet<_>>();
        assert_eq!(
            labels.len(),
            unique.len(),
            "formal_labels must not contain duplicates for {operation_id}"
        );
        for label in &labels {
            assert!(
                rule_ids.contains(*label),
                "formal label {label} is not a known step constructor for {operation_id}"
            );
        }

        let theorem_obligations = mapping
            .get("theorem_obligations")
            .and_then(Value::as_array)
            .expect("theorem_obligations must be an array");
        assert!(
            !theorem_obligations.is_empty(),
            "theorem_obligations must be non-empty for {operation_id}"
        );

        for theorem in theorem_obligations {
            let theorem_name = theorem
                .get("theorem")
                .and_then(Value::as_str)
                .expect("theorem obligation must include theorem");
            let theorem_line = theorem
                .get("line")
                .and_then(Value::as_u64)
                .expect("theorem obligation must include line");
            let expected = theorem_lines
                .get(theorem_name)
                .unwrap_or_else(|| panic!("unknown theorem obligation: {theorem_name}"));
            assert_eq!(
                theorem_line, *expected,
                "line drift for theorem {theorem_name} in {operation_id}"
            );
        }

        let assumptions = mapping
            .get("assumptions")
            .and_then(Value::as_array)
            .expect("assumptions must be an array");
        assert!(
            !assumptions.is_empty(),
            "assumptions must be non-empty for {operation_id}"
        );
        for assumption in assumptions {
            assert!(
                assumption
                    .as_str()
                    .is_some_and(|value| !value.trim().is_empty()),
                "assumption entries must be non-empty for {operation_id}"
            );
        }

        let disambiguation_notes = mapping
            .get("disambiguation_notes")
            .and_then(Value::as_array)
            .expect("disambiguation_notes must be an array");
        if labels.len() > 1 {
            assert!(
                !disambiguation_notes.is_empty(),
                "multi-label mapping must include disambiguation notes for {operation_id}"
            );
        }

        if matches!(
            operation_id,
            "scheduler.three_lane.next_task" | "scope.race_all_loser_drain"
        ) {
            let signatures = mapping
                .get("expected_trace_signatures")
                .and_then(Value::as_array)
                .expect("expected_trace_signatures must be an array for scheduler/combinator rows");
            assert!(
                !signatures.is_empty(),
                "expected_trace_signatures must be non-empty for {operation_id}"
            );
            let signature_values = signatures
                .iter()
                .map(|value| {
                    value
                        .as_str()
                        .expect("expected_trace_signatures values must be strings")
                })
                .collect::<Vec<_>>();
            let unique_signatures = signature_values.iter().copied().collect::<BTreeSet<_>>();
            assert_eq!(
                signature_values.len(),
                unique_signatures.len(),
                "expected_trace_signatures must not contain duplicates for {operation_id}"
            );
            for signature in &signature_values {
                assert!(
                    !signature.trim().is_empty(),
                    "expected_trace_signatures entries must be non-empty for {operation_id}"
                );
            }

            let conformance_links = mapping
                .get("conformance_test_links")
                .and_then(Value::as_array)
                .expect("conformance_test_links must be an array for scheduler/combinator rows");
            assert!(
                !conformance_links.is_empty(),
                "conformance_test_links must be non-empty for {operation_id}"
            );
            for link in conformance_links {
                assert!(
                    link.as_str().is_some_and(|value| !value.trim().is_empty()),
                    "conformance_test_links entries must be non-empty for {operation_id}"
                );
            }
        }
    }
}

#[test]
#[allow(clippy::too_many_lines)]
fn runtime_state_refinement_map_has_deterministic_divergence_routing_policy() {
    let map: Value =
        serde_json::from_str(MAP_JSON).expect("runtime state refinement map must parse");

    let matrix = map
        .get("divergence_triage_decision_matrix")
        .expect("divergence_triage_decision_matrix must exist");
    assert_eq!(
        matrix
            .get("matrix_id")
            .and_then(Value::as_str)
            .expect("matrix_id must be string"),
        "lean.divergence_repair_decision.v1"
    );

    let routes = matrix
        .get("decision_routes")
        .and_then(Value::as_array)
        .expect("decision_routes must be an array");
    assert!(
        !routes.is_empty(),
        "decision_routes must contain at least one route"
    );

    let mut route_ids = BTreeSet::new();
    for route in routes {
        let route_id = route
            .get("route_id")
            .and_then(Value::as_str)
            .expect("route_id must be string");
        assert!(
            route_ids.insert(route_id.to_string()),
            "duplicate route_id: {route_id}"
        );

        let trigger_conditions = route
            .get("trigger_conditions")
            .and_then(Value::as_array)
            .expect("trigger_conditions must be array");
        assert!(
            !trigger_conditions.is_empty(),
            "trigger_conditions must be non-empty for {route_id}"
        );

        let required_evidence = route
            .get("required_evidence")
            .and_then(Value::as_array)
            .expect("required_evidence must be array");
        assert!(
            !required_evidence.is_empty(),
            "required_evidence must be non-empty for {route_id}"
        );

        let patch_targets = route
            .get("patch_targets")
            .and_then(Value::as_array)
            .expect("patch_targets must be array");
        assert!(
            !patch_targets.is_empty(),
            "patch_targets must be non-empty for {route_id}"
        );
        let fix_direction = route
            .get("fix_direction")
            .and_then(Value::as_str)
            .expect("fix_direction must be a string");
        assert!(
            matches!(
                fix_direction,
                "runtime-code" | "formal-model" | "assumption-harness"
            ),
            "fix_direction must be canonical for {route_id}"
        );

        let owner_assignment = route
            .get("owner_assignment")
            .expect("owner_assignment must exist");
        for key in [
            "primary_owner_role",
            "secondary_owner_role",
            "escalation_owner_role",
        ] {
            assert!(
                owner_assignment
                    .get(key)
                    .and_then(Value::as_str)
                    .is_some_and(|value| !value.trim().is_empty()),
                "owner_assignment.{key} must be non-empty for {route_id}"
            );
        }

        let required_artifact_updates = route
            .get("required_artifact_updates")
            .and_then(Value::as_array)
            .expect("required_artifact_updates must be array");
        assert!(
            !required_artifact_updates.is_empty(),
            "required_artifact_updates must be non-empty for {route_id}"
        );
        for artifact in required_artifact_updates {
            assert!(
                artifact
                    .as_str()
                    .is_some_and(|value| !value.trim().is_empty()),
                "required_artifact_updates entries must be non-empty for {route_id}"
            );
        }

        let ci_refs = route
            .get("ci_conformance_failure_references")
            .and_then(Value::as_array)
            .expect("ci_conformance_failure_references must be array");
        assert!(
            !ci_refs.is_empty(),
            "ci_conformance_failure_references must be non-empty for {route_id}"
        );
        for ci_ref in ci_refs {
            assert!(
                ci_ref
                    .as_str()
                    .is_some_and(|value| !value.trim().is_empty()),
                "ci_conformance_failure_references entries must be non-empty for {route_id}"
            );
        }

        let sign_off_roles = route
            .get("sign_off_roles")
            .and_then(Value::as_array)
            .expect("sign_off_roles must be array");
        assert!(
            !sign_off_roles.is_empty(),
            "sign_off_roles must be non-empty for {route_id}"
        );
    }

    let expected_routes = BTreeSet::from([
        "code-first".to_string(),
        "model-first".to_string(),
        "assumptions-or-harness-first".to_string(),
    ]);
    assert_eq!(
        route_ids, expected_routes,
        "divergence decision matrix must contain the canonical route set"
    );

    let audit_requirements = matrix
        .get("audit_requirements")
        .and_then(Value::as_array)
        .expect("audit_requirements must be array");
    assert!(
        !audit_requirements.is_empty(),
        "audit_requirements must be non-empty"
    );

    let examples = map
        .get("divergence_triage_examples")
        .and_then(Value::as_array)
        .expect("divergence_triage_examples must be array");
    assert!(
        !examples.is_empty(),
        "divergence_triage_examples must contain at least one example"
    );

    let mut has_model_first_example = false;
    for example in examples {
        let route = example
            .get("selected_route")
            .and_then(Value::as_str)
            .expect("example selected_route must be string");
        assert!(
            expected_routes.contains(route),
            "example selected_route must map to a canonical route: {route}"
        );
        if route == "model-first" {
            has_model_first_example = true;
        }

        let rejected_routes = example
            .get("rejected_routes")
            .and_then(Value::as_array)
            .expect("example rejected_routes must be array");
        assert!(
            !rejected_routes.is_empty(),
            "rejected_routes must be non-empty for route {route}"
        );
        for rejected in rejected_routes {
            let rejected_route = rejected
                .as_str()
                .expect("rejected_routes values must be strings");
            assert!(
                expected_routes.contains(rejected_route),
                "rejected route must be canonical: {rejected_route}"
            );
            assert_ne!(
                rejected_route, route,
                "selected route cannot appear in rejected_routes"
            );
        }

        let bead_id = example
            .get("bead_id")
            .and_then(Value::as_str)
            .expect("example bead_id must be string");
        assert!(
            bead_id.starts_with("bd-"),
            "example bead_id should be a canonical bead id: {bead_id}"
        );

        let owner_assignment_decision = example
            .get("owner_assignment_decision")
            .expect("owner_assignment_decision must exist");
        for key in [
            "primary_owner_role",
            "assigned_bead_owner",
            "escalation_owner_role",
        ] {
            assert!(
                owner_assignment_decision
                    .get(key)
                    .and_then(Value::as_str)
                    .is_some_and(|value| !value.trim().is_empty()),
                "owner_assignment_decision.{key} must be non-empty for bead {bead_id}"
            );
        }

        let rationale = example
            .get("decision_rationale")
            .and_then(Value::as_array)
            .expect("decision_rationale must be array");
        assert!(
            !rationale.is_empty(),
            "decision_rationale must be non-empty for bead {bead_id}"
        );

        let evidence = example
            .get("evidence")
            .and_then(Value::as_array)
            .expect("example evidence must be array");
        assert!(
            !evidence.is_empty(),
            "evidence must be non-empty for bead {bead_id}"
        );
        for entry in evidence {
            assert!(
                entry
                    .get("artifact")
                    .and_then(Value::as_str)
                    .is_some_and(|artifact| !artifact.trim().is_empty()),
                "evidence artifact must be non-empty for bead {bead_id}"
            );
        }

        let artifact_updates = example
            .get("artifact_updates")
            .and_then(Value::as_array)
            .expect("artifact_updates must be array");
        assert!(
            !artifact_updates.is_empty(),
            "artifact_updates must be non-empty for bead {bead_id}"
        );
        for artifact in artifact_updates {
            assert!(
                artifact
                    .as_str()
                    .is_some_and(|value| !value.trim().is_empty()),
                "artifact_updates entries must be non-empty for bead {bead_id}"
            );
        }

        let ci_reference = example
            .get("ci_conformance_reference")
            .expect("ci_conformance_reference must exist");
        for key in ["profile", "failure_bucket", "conformance_test"] {
            assert!(
                ci_reference
                    .get(key)
                    .and_then(Value::as_str)
                    .is_some_and(|value| !value.trim().is_empty()),
                "ci_conformance_reference.{key} must be non-empty for bead {bead_id}"
            );
        }

        let sign_off_roles = example
            .get("sign_off_roles")
            .and_then(Value::as_array)
            .expect("example sign_off_roles must be array");
        assert!(
            !sign_off_roles.is_empty(),
            "sign_off_roles must be non-empty for bead {bead_id}"
        );
    }

    assert!(
        has_model_first_example,
        "at least one divergence example must exercise model-first routing"
    );
}

#[test]
#[allow(clippy::too_many_lines)]
fn runtime_state_refinement_map_conformance_harness_contract_is_complete() {
    let map: Value =
        serde_json::from_str(MAP_JSON).expect("runtime state refinement map must parse");
    let contract = map
        .get("conformance_harness_contract")
        .expect("conformance_harness_contract must exist");

    assert_eq!(
        contract
            .get("contract_id")
            .and_then(Value::as_str)
            .expect("contract_id must be string"),
        "lean.runtime_state_refinement_conformance.v1"
    );
    assert_eq!(
        contract
            .get("artifact_schema_version")
            .and_then(Value::as_str)
            .expect("artifact_schema_version must be string"),
        "1.0.0"
    );

    let determinism = contract
        .get("determinism_requirements")
        .expect("determinism_requirements must exist");
    for key in ["seed_source", "trace_normalization", "clock_source"] {
        assert!(
            determinism
                .get(key)
                .and_then(Value::as_str)
                .is_some_and(|value| !value.trim().is_empty()),
            "determinism_requirements.{key} must be non-empty"
        );
    }
    let forbidden_entropy_sources = determinism
        .get("forbidden_entropy_sources")
        .and_then(Value::as_array)
        .expect("forbidden_entropy_sources must be an array");
    assert!(
        forbidden_entropy_sources.len() >= 3,
        "forbidden_entropy_sources must list stable disallowed entropy sources"
    );

    let mismatch_payload_fields = contract
        .get("mismatch_payload_fields")
        .and_then(Value::as_array)
        .expect("mismatch_payload_fields must be an array")
        .iter()
        .map(|field| {
            field
                .as_str()
                .expect("mismatch_payload_fields values must be strings")
        })
        .collect::<BTreeSet<_>>();
    for field in [
        "harness_id",
        "scenario_id",
        "first_divergence_index",
        "expected_signature",
        "observed_signature",
        "counterexample_event_window",
        "route_candidates",
        "recommended_route",
    ] {
        assert!(
            mismatch_payload_fields.contains(field),
            "missing mismatch payload field {field}"
        );
    }

    let repro_manifest_fields = contract
        .get("repro_manifest_fields")
        .and_then(Value::as_array)
        .expect("repro_manifest_fields must be an array")
        .iter()
        .map(|field| {
            field
                .as_str()
                .expect("repro_manifest_fields values must be strings")
        })
        .collect::<BTreeSet<_>>();
    for field in [
        "command",
        "toolchain",
        "seed",
        "input_artifacts",
        "output_artifacts",
        "comparison_keys",
    ] {
        assert!(
            repro_manifest_fields.contains(field),
            "missing repro manifest field {field}"
        );
    }

    let harnesses = contract
        .get("harnesses")
        .and_then(Value::as_array)
        .expect("harnesses must be an array");
    assert!(!harnesses.is_empty(), "harnesses must not be empty");

    let mut harness_ids = BTreeSet::new();
    let mut has_cancel_obligation_harness = false;
    let mut has_race_loser_harness = false;

    for harness in harnesses {
        let harness_id = harness
            .get("harness_id")
            .and_then(Value::as_str)
            .expect("harness_id must be string");
        assert!(
            harness_ids.insert(harness_id.to_string()),
            "duplicate harness_id: {harness_id}"
        );

        assert!(
            harness
                .get("purpose")
                .and_then(Value::as_str)
                .is_some_and(|value| !value.trim().is_empty()),
            "purpose must be non-empty for harness {harness_id}"
        );

        let scenario_ids = harness
            .get("scenario_ids")
            .and_then(Value::as_array)
            .expect("scenario_ids must be array");
        assert!(
            !scenario_ids.is_empty(),
            "scenario_ids must be non-empty for harness {harness_id}"
        );
        let scenario_values = scenario_ids
            .iter()
            .map(|value| value.as_str().expect("scenario_ids values must be strings"))
            .collect::<Vec<_>>();
        let scenario_unique = scenario_values.iter().copied().collect::<BTreeSet<_>>();
        assert_eq!(
            scenario_values.len(),
            scenario_unique.len(),
            "scenario_ids must be unique for harness {harness_id}"
        );

        let formal_expectations = harness
            .get("formal_expectations")
            .and_then(Value::as_array)
            .expect("formal_expectations must be array");
        assert!(
            !formal_expectations.is_empty(),
            "formal_expectations must be non-empty for harness {harness_id}"
        );

        for key in [
            "normalized_trace_artifact",
            "mismatch_payload_artifact",
            "repro_manifest_artifact",
        ] {
            let artifact = harness
                .get(key)
                .and_then(Value::as_str)
                .expect("artifact path must be string");
            assert!(
                artifact.starts_with("target/refinement-conformance/")
                    && std::path::Path::new(artifact)
                        .extension()
                        .is_some_and(|ext| ext.eq_ignore_ascii_case("json")),
                "artifact path must be deterministic and JSON for {harness_id}: {key}"
            );
        }

        let conformance_test_links = harness
            .get("conformance_test_links")
            .and_then(Value::as_array)
            .expect("conformance_test_links must be array");
        assert!(
            !conformance_test_links.is_empty(),
            "conformance_test_links must be non-empty for harness {harness_id}"
        );
        for link in conformance_test_links {
            assert!(
                link.as_str()
                    .is_some_and(|value| value.starts_with("tests/refinement_conformance.rs:")),
                "conformance_test_links must reference refinement_conformance tests for {harness_id}"
            );
        }

        if harness_id == "harness.cancellation_obligation" {
            has_cancel_obligation_harness = true;
            assert!(
                scenario_values
                    .iter()
                    .any(|value| value.contains("cancel") || value.contains("obligation")),
                "cancellation/obligation harness must include cancellation or obligation scenario ids"
            );
        }
        if harness_id == "harness.race_loser_drain" {
            has_race_loser_harness = true;
            assert!(
                scenario_values
                    .iter()
                    .any(|value| value.contains("race") || value.contains("mismatch")),
                "race loser-drain harness must include race/mismatch scenario ids"
            );
        }
    }

    assert!(
        has_cancel_obligation_harness,
        "contract must include a cancellation/obligation harness"
    );
    assert!(
        has_race_loser_harness,
        "contract must include a race/loser-drain harness"
    );

    let ci_consumers = contract
        .get("ci_consumers")
        .and_then(Value::as_array)
        .expect("ci_consumers must be an array");
    assert!(!ci_consumers.is_empty(), "ci_consumers must not be empty");

    let mut seen_profiles = BTreeSet::new();
    for consumer in ci_consumers {
        let profile = consumer
            .get("profile")
            .and_then(Value::as_str)
            .expect("ci_consumers.profile must be string");
        seen_profiles.insert(profile);

        let required_harness_ids = consumer
            .get("required_harness_ids")
            .and_then(Value::as_array)
            .expect("required_harness_ids must be an array");
        assert!(
            !required_harness_ids.is_empty(),
            "required_harness_ids must be non-empty for profile {profile}"
        );
        for required_harness_id in required_harness_ids {
            let required_id = required_harness_id
                .as_str()
                .expect("required_harness_ids values must be strings");
            assert!(
                harness_ids.contains(required_id),
                "profile {profile} references unknown harness id {required_id}"
            );
        }

        let required_artifacts = consumer
            .get("required_artifacts")
            .and_then(Value::as_array)
            .expect("required_artifacts must be an array")
            .iter()
            .map(|artifact| {
                artifact
                    .as_str()
                    .expect("required_artifacts values must be strings")
            })
            .collect::<BTreeSet<_>>();
        for artifact_key in [
            "normalized_trace_artifact",
            "mismatch_payload_artifact",
            "repro_manifest_artifact",
        ] {
            assert!(
                required_artifacts.contains(artifact_key),
                "required_artifacts missing {artifact_key} for profile {profile}"
            );
        }

        let triage_route_reference = consumer
            .get("triage_route_reference")
            .and_then(Value::as_str)
            .expect("triage_route_reference must be string");
        assert!(
            matches!(
                triage_route_reference,
                "code-first" | "model-first" | "assumptions-or-harness-first"
            ),
            "ci_consumers triage_route_reference must be canonical for profile {profile}"
        );
    }

    for profile in ["frontier", "full"] {
        assert!(
            seen_profiles.contains(profile),
            "ci_consumers must define profile {profile}"
        );
    }
}

#[test]
#[allow(clippy::too_many_lines)]
fn runtime_state_refinement_map_reporting_and_signoff_contract_is_complete() {
    let map: Value =
        serde_json::from_str(MAP_JSON).expect("runtime state refinement map must parse");
    let contract = map
        .get("reporting_and_signoff_contract")
        .expect("reporting_and_signoff_contract must exist");

    assert_eq!(
        contract
            .get("contract_id")
            .and_then(Value::as_str)
            .expect("contract_id must be string"),
        "lean.refinement_conformance_reporting_signoff.v1"
    );
    assert_eq!(
        contract
            .get("artifact_schema_version")
            .and_then(Value::as_str)
            .expect("artifact_schema_version must be string"),
        "1.0.0"
    );

    let cadence = contract
        .get("report_cadence")
        .and_then(Value::as_array)
        .expect("report_cadence must be array");
    assert!(cadence.len() >= 2, "report_cadence must define review rhythms");

    let mut cadence_ids = BTreeSet::new();
    for entry in cadence {
        let cadence_id = entry
            .get("cadence_id")
            .and_then(Value::as_str)
            .expect("cadence_id must be string");
        assert!(
            cadence_ids.insert(cadence_id),
            "duplicate cadence_id: {cadence_id}"
        );
        assert!(
            entry.get("governance_record_thread")
                .and_then(Value::as_str)
                .is_some_and(|value| !value.trim().is_empty()),
            "governance_record_thread must be non-empty for cadence {cadence_id}"
        );
        let participants = entry
            .get("required_participants")
            .and_then(Value::as_array)
            .expect("required_participants must be array");
        assert!(
            !participants.is_empty(),
            "required_participants must be non-empty for cadence {cadence_id}"
        );
    }
    for expected in ["weekly", "phase-exit"] {
        assert!(
            cadence_ids.contains(expected),
            "report_cadence must include {expected}"
        );
    }

    let ownership_roles = contract
        .get("ownership_roles")
        .expect("ownership_roles must exist");
    for key in ["report_owner_role", "escalation_owner_role"] {
        assert!(
            ownership_roles
                .get(key)
                .and_then(Value::as_str)
                .is_some_and(|value| !value.trim().is_empty()),
            "ownership_roles.{key} must be non-empty"
        );
    }
    let signoff_roles = ownership_roles
        .get("signoff_approver_roles")
        .and_then(Value::as_array)
        .expect("signoff_approver_roles must be array");
    assert!(
        !signoff_roles.is_empty(),
        "signoff_approver_roles must be non-empty"
    );

    let governance_links = contract
        .get("governance_links")
        .and_then(Value::as_array)
        .expect("governance_links must be array")
        .iter()
        .map(|value| value.as_str().expect("governance link must be string"))
        .collect::<BTreeSet<_>>();
    for required_link in ["asupersync-38g6z", "bd-3gnw9"] {
        assert!(
            governance_links.contains(required_link),
            "governance_links must include {required_link}"
        );
    }

    let required_report_fields = contract
        .get("required_report_fields")
        .and_then(Value::as_array)
        .expect("required_report_fields must be array")
        .iter()
        .map(|value| {
            value
                .as_str()
                .expect("required_report_fields value must be string")
        })
        .collect::<BTreeSet<_>>();
    for field in [
        "coverage_percent",
        "mismatch_trend",
        "unresolved_blockers",
        "confidence_statement",
        "generated_at",
    ] {
        assert!(
            required_report_fields.contains(field),
            "required_report_fields missing {field}"
        );
    }

    let required_artifact_refs = contract
        .get("required_artifact_refs")
        .and_then(Value::as_array)
        .expect("required_artifact_refs must be array");
    assert!(
        !required_artifact_refs.is_empty(),
        "required_artifact_refs must be non-empty"
    );
    let required_test_refs = contract
        .get("required_test_refs")
        .and_then(Value::as_array)
        .expect("required_test_refs must be array");
    assert!(
        required_test_refs
            .iter()
            .any(|value| value.as_str() == Some("tests/refinement_conformance.rs")),
        "required_test_refs must include tests/refinement_conformance.rs"
    );
    assert!(
        required_test_refs
            .iter()
            .any(|value| value.as_str() == Some("tests/runtime_state_refinement_map.rs")),
        "required_test_refs must include tests/runtime_state_refinement_map.rs"
    );

    let checklist = contract
        .get("signoff_checklist")
        .and_then(Value::as_array)
        .expect("signoff_checklist must be array");
    assert!(!checklist.is_empty(), "signoff_checklist must be non-empty");
    for item in checklist {
        assert!(
            item.get("check_id")
                .and_then(Value::as_str)
                .is_some_and(|value| !value.trim().is_empty()),
            "checklist check_id must be non-empty"
        );
        assert!(
            item.get("description")
                .and_then(Value::as_str)
                .is_some_and(|value| !value.trim().is_empty()),
            "checklist description must be non-empty"
        );
        for key in ["required_artifacts", "required_tests"] {
            let refs = item
                .get(key)
                .and_then(Value::as_array)
                .expect("checklist refs must be arrays");
            assert!(!refs.is_empty(), "checklist {key} must be non-empty");
        }
        assert!(
            item.get("pass_criteria")
                .and_then(Value::as_str)
                .is_some_and(|value| !value.trim().is_empty()),
            "checklist pass_criteria must be non-empty"
        );
    }

    let latest_report = contract
        .get("latest_report")
        .expect("latest_report must exist");
    for key in [
        "report_id",
        "generated_at",
        "mismatch_trend",
        "unresolved_blockers",
        "confidence_statement",
    ] {
        assert!(
            latest_report.get(key).is_some(),
            "latest_report missing key {key}"
        );
    }

    let coverage_percent = latest_report
        .get("coverage_percent")
        .expect("latest_report.coverage_percent must exist");
    for key in ["mapped_operations", "conformance_harnesses", "invariant_test_links"] {
        let value = coverage_percent
            .get(key)
            .and_then(Value::as_f64)
            .expect("coverage_percent values must be numeric");
        assert!(
            (0.0..=100.0).contains(&value),
            "coverage_percent.{key} must be in [0, 100]"
        );
    }

    let mismatch_trend = latest_report
        .get("mismatch_trend")
        .expect("mismatch_trend must exist");
    assert!(
        mismatch_trend
            .get("window")
            .and_then(Value::as_str)
            .is_some_and(|value| !value.trim().is_empty()),
        "mismatch_trend.window must be non-empty"
    );
    assert!(
        mismatch_trend
            .get("trend")
            .and_then(Value::as_str)
            .is_some_and(|trend| matches!(trend, "improving" | "flat" | "regressing")),
        "mismatch_trend.trend must be canonical"
    );

    let unresolved_blockers = latest_report
        .get("unresolved_blockers")
        .and_then(Value::as_array)
        .expect("unresolved_blockers must be array");
    for blocker in unresolved_blockers {
        let bead_id = blocker
            .get("bead_id")
            .and_then(Value::as_str)
            .expect("unresolved_blockers.bead_id must be string");
        assert!(
            bead_id.starts_with("asupersync-") || bead_id.starts_with("bd-"),
            "unresolved_blockers.bead_id must use canonical id format"
        );
        assert!(
            blocker
                .get("status")
                .and_then(Value::as_str)
                .is_some_and(|value| matches!(value, "open" | "in_progress" | "blocked")),
            "unresolved_blockers.status must be canonical for {bead_id}"
        );
        assert!(
            blocker
                .get("next_action")
                .and_then(Value::as_str)
                .is_some_and(|value| !value.trim().is_empty()),
            "unresolved_blockers.next_action must be non-empty for {bead_id}"
        );
    }

    let confidence = latest_report
        .get("confidence_statement")
        .expect("confidence_statement must exist");
    assert!(
        confidence
            .get("level")
            .and_then(Value::as_str)
            .is_some_and(|value| matches!(value, "high" | "medium" | "low")),
        "confidence_statement.level must be canonical"
    );
    assert!(
        confidence
            .get("rationale")
            .and_then(Value::as_str)
            .is_some_and(|value| !value.trim().is_empty()),
        "confidence_statement.rationale must be non-empty"
    );

    let track6_contract = contract
        .get("track6_input_contract")
        .expect("track6_input_contract must exist");
    let consumer_beads = track6_contract
        .get("consumer_beads")
        .and_then(Value::as_array)
        .expect("consumer_beads must be array")
        .iter()
        .map(|value| value.as_str().expect("consumer bead id must be string"))
        .collect::<BTreeSet<_>>();
    for bead in ["asupersync-2izu4", "asupersync-3gf4i"] {
        assert!(
            consumer_beads.contains(bead),
            "track6_input_contract must include consumer bead {bead}"
        );
    }

    let export_fields = track6_contract
        .get("export_fields")
        .and_then(Value::as_array)
        .expect("export_fields must be array")
        .iter()
        .map(|value| value.as_str().expect("export field must be string"))
        .collect::<BTreeSet<_>>();
    for field in [
        "coverage_percent",
        "mismatch_trend",
        "unresolved_blockers",
        "confidence_statement",
        "next_actions",
    ] {
        assert!(
            export_fields.contains(field),
            "track6_input_contract.export_fields missing {field}"
        );
    }
    assert!(
        track6_contract
            .get("handoff_rule")
            .and_then(Value::as_str)
            .is_some_and(|value| !value.trim().is_empty()),
        "track6_input_contract.handoff_rule must be non-empty"
    );
}
