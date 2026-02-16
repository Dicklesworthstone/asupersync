//! Lean theorem inventory and constructor coverage consistency tests (bd-3n3b2).

use serde_json::Value;
use std::collections::BTreeSet;

const THEOREM_INVENTORY_JSON: &str =
    include_str!("../formal/lean/coverage/theorem_surface_inventory.json");
const STEP_COVERAGE_JSON: &str =
    include_str!("../formal/lean/coverage/step_constructor_coverage.json");

#[test]
fn theorem_inventory_is_well_formed() {
    let inventory: Value =
        serde_json::from_str(THEOREM_INVENTORY_JSON).expect("theorem inventory must parse");
    let theorem_count = inventory
        .get("theorem_count")
        .and_then(Value::as_u64)
        .expect("theorem_count must be present");
    let theorems = inventory
        .get("theorems")
        .and_then(Value::as_array)
        .expect("theorems must be an array");
    assert_eq!(theorem_count as usize, theorems.len());

    let names = theorems
        .iter()
        .map(|entry| {
            entry
                .get("theorem")
                .and_then(Value::as_str)
                .expect("theorem name must be a string")
        })
        .collect::<Vec<_>>();
    assert_eq!(names.len(), names.iter().collect::<BTreeSet<_>>().len());
}

#[test]
fn theorem_inventory_lines_are_positive_and_unique() {
    let inventory: Value =
        serde_json::from_str(THEOREM_INVENTORY_JSON).expect("theorem inventory must parse");
    let theorems = inventory
        .get("theorems")
        .and_then(Value::as_array)
        .expect("theorems must be an array");

    let mut seen_lines = BTreeSet::new();
    for entry in theorems {
        let theorem = entry
            .get("theorem")
            .and_then(Value::as_str)
            .expect("theorem name must be present");
        let line = entry
            .get("line")
            .and_then(Value::as_u64)
            .expect("theorem line must be numeric");
        assert!(line > 0, "theorem {theorem} must have positive line");
        assert!(
            seen_lines.insert(line),
            "theorem inventory has duplicate line {line}; expected stable 1:1 theorem-to-line mapping (latest theorem: {theorem})"
        );
    }
}

#[test]
fn step_constructor_coverage_is_consistent() {
    let coverage: Value =
        serde_json::from_str(STEP_COVERAGE_JSON).expect("step coverage must parse");
    let constructors = coverage
        .get("constructors")
        .and_then(Value::as_array)
        .expect("constructors must be an array");
    assert_eq!(constructors.len(), 22, "Step should have 22 constructors");

    let names = constructors
        .iter()
        .map(|entry| {
            entry
                .get("constructor")
                .and_then(Value::as_str)
                .expect("constructor name must be a string")
        })
        .collect::<Vec<_>>();
    assert_eq!(names.len(), names.iter().collect::<BTreeSet<_>>().len());

    let partial = constructors
        .iter()
        .filter_map(|entry| {
            let status = entry.get("status").and_then(Value::as_str)?;
            if status == "partial" {
                entry.get("constructor").and_then(Value::as_str)
            } else {
                None
            }
        })
        .collect::<BTreeSet<_>>();

    let summary_partial = coverage
        .pointer("/summary/partial_constructors")
        .and_then(Value::as_array)
        .expect("summary.partial_constructors must exist")
        .iter()
        .filter_map(Value::as_str)
        .collect::<BTreeSet<_>>();
    assert_eq!(partial, summary_partial);
}

#[test]
fn mapped_theorems_exist_in_inventory() {
    let inventory: Value =
        serde_json::from_str(THEOREM_INVENTORY_JSON).expect("theorem inventory must parse");
    let theorem_names = inventory
        .get("theorems")
        .and_then(Value::as_array)
        .expect("theorems must be an array")
        .iter()
        .filter_map(|entry| entry.get("theorem").and_then(Value::as_str))
        .collect::<BTreeSet<_>>();

    let coverage: Value =
        serde_json::from_str(STEP_COVERAGE_JSON).expect("step coverage must parse");
    let constructors = coverage
        .get("constructors")
        .and_then(Value::as_array)
        .expect("constructors must be an array");

    for constructor in constructors {
        let name = constructor
            .get("constructor")
            .and_then(Value::as_str)
            .expect("constructor must have a name");
        let mapped = constructor
            .get("mapped_theorems")
            .and_then(Value::as_array)
            .expect("constructor must have mapped_theorems");
        assert!(
            !mapped.is_empty(),
            "constructor {name} must map to at least one theorem"
        );
        for theorem in mapped {
            let theorem_name = theorem
                .as_str()
                .expect("mapped theorem names must be strings");
            assert!(
                theorem_names.contains(theorem_name),
                "constructor {name} maps to unknown theorem {theorem_name}"
            );
        }
    }
}

#[test]
fn progress_and_canonical_families_cover_required_ladders() {
    let inventory: Value =
        serde_json::from_str(THEOREM_INVENTORY_JSON).expect("theorem inventory must parse");
    let theorem_names = inventory
        .get("theorems")
        .and_then(Value::as_array)
        .expect("theorems must be an array")
        .iter()
        .filter_map(|entry| entry.get("theorem").and_then(Value::as_str))
        .collect::<BTreeSet<_>>();

    let required_cancel_ladder = BTreeSet::from([
        "cancel_masked_step",
        "cancel_ack_step",
        "cancel_finalize_step",
        "cancel_complete_step",
        "cancel_protocol_terminates",
        "cancel_propagation_bounded",
    ]);
    let required_close_ladder = BTreeSet::from([
        "close_begin_step",
        "close_cancel_children_step",
        "close_children_done_step",
        "close_run_finalizer_step",
        "close_complete_step",
        "close_implies_quiescent",
        "close_quiescence_decomposition",
    ]);
    let required_obligation_lifecycle = BTreeSet::from([
        "reserve_creates_reserved",
        "commit_resolves",
        "abort_resolves",
        "leak_marks_leaked",
        "committed_obligation_stable",
        "aborted_obligation_stable",
        "leaked_obligation_stable",
        "resolved_obligation_stable",
    ]);
    let required_task_canonical_forms = BTreeSet::from([
        "task_cancel_requested_canonical_form",
        "task_cancelling_canonical_form",
        "task_finalizing_canonical_form",
    ]);
    let required_region_canonical_forms = BTreeSet::from([
        "region_closing_canonical_form",
        "region_draining_canonical_form",
        "region_finalizing_canonical_form",
    ]);
    let required_obligation_canonical_forms = BTreeSet::from([
        "obligation_reserved_canonical_form",
        "obligation_committed_canonical_form",
        "obligation_aborted_canonical_form",
        "obligation_leaked_canonical_form",
    ]);

    for theorem in required_cancel_ladder
        .iter()
        .chain(required_close_ladder.iter())
        .chain(required_obligation_lifecycle.iter())
        .chain(required_task_canonical_forms.iter())
        .chain(required_region_canonical_forms.iter())
        .chain(required_obligation_canonical_forms.iter())
    {
        assert!(
            theorem_names.contains(theorem),
            "required theorem missing from inventory: {theorem}"
        );
    }
}

#[test]
fn liveness_bundle_theorems_cover_termination_and_quiescence_contract() {
    let inventory: Value =
        serde_json::from_str(THEOREM_INVENTORY_JSON).expect("theorem inventory must parse");
    let theorem_names = inventory
        .get("theorems")
        .and_then(Value::as_array)
        .expect("theorems must be an array")
        .iter()
        .filter_map(|entry| entry.get("theorem").and_then(Value::as_str))
        .collect::<BTreeSet<_>>();

    let required_liveness_theorems = BTreeSet::from([
        "cancel_protocol_terminates",
        "cancel_terminates_from_cancelling",
        "cancel_terminates_from_finalizing",
        "cancel_steps_testable_bound",
        "cancel_propagation_bounded",
        "close_implies_quiescent",
        "close_quiescence_decomposition",
        "close_complete_step",
    ]);

    for theorem in required_liveness_theorems {
        assert!(
            theorem_names.contains(theorem),
            "required liveness theorem missing from inventory: {theorem}"
        );
    }
}
