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

        let bead_id = example
            .get("bead_id")
            .and_then(Value::as_str)
            .expect("example bead_id must be string");
        assert!(
            bead_id.starts_with("bd-"),
            "example bead_id should be a canonical bead id: {bead_id}"
        );

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
