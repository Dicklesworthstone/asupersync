//! Constructor-total preservation coverage checks for bd-112rm.

use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

const STEP_COVERAGE_JSON: &str =
    include_str!("../formal/lean/coverage/step_constructor_coverage.json");
const THEOREM_INVENTORY_JSON: &str =
    include_str!("../formal/lean/coverage/theorem_surface_inventory.json");
const TRACEABILITY_LEDGER_JSON: &str =
    include_str!("../formal/lean/coverage/theorem_rule_traceability_ledger.json");

#[test]
fn preservation_constructor_coverage_is_total() {
    let coverage: Value =
        serde_json::from_str(STEP_COVERAGE_JSON).expect("step coverage json must parse");
    let constructors = coverage
        .get("constructors")
        .and_then(Value::as_array)
        .expect("constructors must be an array");

    let mut statuses = BTreeSet::new();
    for constructor in constructors {
        let status = constructor
            .get("status")
            .and_then(Value::as_str)
            .expect("constructor status must be a string");
        statuses.insert(status);
    }
    assert_eq!(
        statuses,
        BTreeSet::from(["covered"]),
        "all step constructors must be covered"
    );

    assert_eq!(
        coverage
            .pointer("/summary/covered")
            .and_then(Value::as_u64)
            .expect("summary.covered must be numeric"),
        22
    );
    assert_eq!(
        coverage
            .pointer("/summary/partial")
            .and_then(Value::as_u64)
            .expect("summary.partial must be numeric"),
        0
    );
    assert_eq!(
        coverage
            .pointer("/summary/missing")
            .and_then(Value::as_u64)
            .expect("summary.missing must be numeric"),
        0
    );
    let partial = coverage
        .pointer("/summary/partial_constructors")
        .and_then(Value::as_array)
        .expect("summary.partial_constructors must be an array");
    assert!(partial.is_empty(), "partial constructor list must be empty");
}

#[test]
fn constructor_specific_preservation_lemmas_are_traceable() {
    let coverage: Value =
        serde_json::from_str(STEP_COVERAGE_JSON).expect("step coverage json must parse");
    let theorem_inventory: Value =
        serde_json::from_str(THEOREM_INVENTORY_JSON).expect("theorem inventory must parse");
    let ledger: Value =
        serde_json::from_str(TRACEABILITY_LEDGER_JSON).expect("traceability ledger must parse");

    let theorem_names = theorem_inventory
        .get("theorems")
        .and_then(Value::as_array)
        .expect("theorems must be an array")
        .iter()
        .map(|entry| {
            entry
                .get("theorem")
                .and_then(Value::as_str)
                .expect("theorem name must be a string")
        })
        .collect::<BTreeSet<_>>();

    let constructors = coverage
        .get("constructors")
        .and_then(Value::as_array)
        .expect("constructors must be an array");
    let mapped = constructors
        .iter()
        .map(|entry| {
            let constructor = entry
                .get("constructor")
                .and_then(Value::as_str)
                .expect("constructor name must be string")
                .to_string();
            let theorems = entry
                .get("mapped_theorems")
                .and_then(Value::as_array)
                .expect("mapped_theorems must be an array")
                .iter()
                .map(|t| t.as_str().expect("theorem names must be strings"))
                .collect::<BTreeSet<_>>();
            (constructor, theorems)
        })
        .collect::<BTreeMap<_, _>>();

    let expected = [
        ("enqueue", "enqueue_preserves_wellformed_constructor"),
        (
            "scheduleStep",
            "scheduleStep_preserves_wellformed_constructor",
        ),
        ("schedule", "schedule_preserves_wellformed_constructor"),
        (
            "cancelChild",
            "cancelChild_preserves_wellformed_constructor",
        ),
    ];

    for (constructor, theorem) in expected {
        assert!(
            theorem_names.contains(theorem),
            "constructor-specific theorem {theorem} missing from inventory"
        );
        let mapped_theorems = mapped
            .get(constructor)
            .expect("expected constructor must exist in coverage map");
        assert!(
            mapped_theorems.contains(theorem),
            "constructor {constructor} missing theorem mapping {theorem}"
        );
    }

    let ledger_pairs = ledger
        .get("rows")
        .and_then(Value::as_array)
        .expect("ledger rows must be an array")
        .iter()
        .map(|row| {
            let theorem = row
                .get("theorem")
                .and_then(Value::as_str)
                .expect("ledger theorem must be string");
            let rule_id = row
                .get("rule_id")
                .and_then(Value::as_str)
                .expect("ledger rule_id must be string");
            (theorem, rule_id)
        })
        .collect::<BTreeSet<_>>();

    for (constructor, theorem) in expected {
        let rule_id = format!("step.{constructor}");
        assert!(
            ledger_pairs.contains(&(theorem, rule_id.as_str())),
            "traceability ledger missing pair ({theorem}, {rule_id})"
        );
    }
}
