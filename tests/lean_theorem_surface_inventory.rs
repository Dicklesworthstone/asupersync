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
