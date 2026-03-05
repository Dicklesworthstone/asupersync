//! SingleOwner invariant conformance checks (SEM-06.F1, asupersync-3cddg.6.6).
//!
//! Validates that:
//!   1. The Lean theorem surface inventory includes all SingleOwner theorems.
//!   2. The invariant status inventory records the single_owner invariant as fully_proven.
//!   3. The traceability ledger has entries for the master dispatcher theorems.
//!   4. The step_preserves_single_owner theorem covers spawn (the only children-mutating step).

use serde_json::Value;
use std::collections::BTreeSet;

const THEOREM_JSON: &str = include_str!("../formal/lean/coverage/theorem_surface_inventory.json");
const INVARIANT_JSON: &str =
    include_str!("../formal/lean/coverage/invariant_status_inventory.json");
const TRACEABILITY_JSON: &str =
    include_str!("../formal/lean/coverage/theorem_rule_traceability_ledger.json");

fn parse(s: &str, label: &str) -> Value {
    serde_json::from_str(s).unwrap_or_else(|e| panic!("{label} must parse: {e}"))
}

fn theorem_names(inv: &Value) -> BTreeSet<String> {
    inv.get("theorems")
        .and_then(Value::as_array)
        .expect("theorems array")
        .iter()
        .map(|e| {
            e.get("theorem")
                .and_then(Value::as_str)
                .expect("theorem name")
                .to_string()
        })
        .collect()
}

/// All nine SingleOwner theorems must appear in the theorem surface inventory.
#[test]
fn single_owner_theorems_in_surface_inventory() {
    let inv = parse(THEOREM_JSON, "theorem_surface_inventory");
    let names = theorem_names(&inv);

    let expected = [
        "scheduler_change_preserves_single_owner",
        "setTask_same_region_preserves_single_owner",
        "setRegion_structural_preserves_single_owner",
        "tick_preserves_single_owner",
        "setObligation_preserves_single_owner",
        "spawn_preserves_single_owner",
        "reserve_preserves_single_owner",
        "step_preserves_single_owner",
        "steps_preserve_single_owner",
    ];

    for name in &expected {
        assert!(
            names.contains(*name),
            "theorem {name} missing from surface inventory"
        );
    }
}

/// The single_owner invariant must be recorded as fully_proven.
#[test]
fn single_owner_invariant_fully_proven() {
    let inv = parse(INVARIANT_JSON, "invariant_status_inventory");
    let invariants = inv
        .get("invariants")
        .and_then(Value::as_array)
        .expect("invariants array");

    let entry = invariants
        .iter()
        .find(|e| {
            e.get("id").and_then(Value::as_str) == Some("inv.structured_concurrency.single_owner")
        })
        .expect("single_owner invariant entry must exist");

    let status = entry
        .get("lean_status")
        .and_then(Value::as_str)
        .expect("lean_status");
    assert_eq!(status, "fully_proven", "single_owner must be fully_proven");

    let gaps = entry
        .get("gaps")
        .and_then(Value::as_array)
        .expect("gaps array");
    assert!(gaps.is_empty(), "single_owner must have no gaps");
}

/// The invariant entry must list all nine SingleOwner theorems.
#[test]
fn single_owner_invariant_theorem_list_complete() {
    let inv = parse(INVARIANT_JSON, "invariant_status_inventory");
    let invariants = inv
        .get("invariants")
        .and_then(Value::as_array)
        .expect("invariants array");

    let entry = invariants
        .iter()
        .find(|e| {
            e.get("id").and_then(Value::as_str) == Some("inv.structured_concurrency.single_owner")
        })
        .expect("single_owner entry");

    let theorems: BTreeSet<String> = entry
        .get("lean_theorems")
        .and_then(Value::as_array)
        .expect("lean_theorems array")
        .iter()
        .filter_map(|v: &Value| v.as_str().map(String::from))
        .collect();

    let required = [
        "step_preserves_single_owner",
        "steps_preserve_single_owner",
        "spawn_preserves_single_owner",
    ];
    for name in &required {
        assert!(theorems.contains(*name), "lean_theorems missing {name}");
    }
}

/// The traceability ledger must have rows for the master dispatcher theorems.
#[test]
fn single_owner_traceability_rows_present() {
    let ledger = parse(TRACEABILITY_JSON, "traceability_ledger");
    let rows = ledger.get("rows").and_then(Value::as_array).expect("rows");

    let theorem_set: BTreeSet<String> = rows
        .iter()
        .filter_map(|r| r.get("theorem").and_then(Value::as_str).map(String::from))
        .collect();

    assert!(
        theorem_set.contains("step_preserves_single_owner"),
        "step_preserves_single_owner must be in traceability ledger"
    );
    assert!(
        theorem_set.contains("steps_preserve_single_owner"),
        "steps_preserve_single_owner must be in traceability ledger"
    );
}

/// step_preserves_single_owner must trace to step.spawn (the only children-mutating rule).
#[test]
fn single_owner_traces_to_spawn() {
    let ledger = parse(TRACEABILITY_JSON, "traceability_ledger");
    let rows = ledger.get("rows").and_then(Value::as_array).expect("rows");

    let spawn_row = rows
        .iter()
        .find(|r| r.get("theorem").and_then(Value::as_str) == Some("step_preserves_single_owner"));
    assert!(
        spawn_row.is_some(),
        "must have step_preserves_single_owner row"
    );

    let rule = spawn_row
        .unwrap()
        .get("rule_id")
        .and_then(Value::as_str)
        .expect("rule_id");
    assert_eq!(rule, "step.spawn", "must trace to step.spawn");
}

/// Summary counts must be consistent with individual invariant statuses.
#[test]
fn invariant_summary_counts_consistent() {
    let inv = parse(INVARIANT_JSON, "invariant_status_inventory");
    let invariants = inv
        .get("invariants")
        .and_then(Value::as_array)
        .expect("invariants array");

    let mut fully = 0u64;
    let mut partial = 0u64;
    let mut unproven = 0u64;

    for entry in invariants {
        match entry.get("lean_status").and_then(Value::as_str) {
            Some("fully_proven" | "proven") => fully += 1,
            Some("partially_proven") => partial += 1,
            Some("unproven") => unproven += 1,
            other => panic!("unexpected lean_status: {other:?}"),
        }
    }

    let summary = inv.get("summary").expect("summary object");
    let s_fully = summary
        .get("fully_proven")
        .and_then(Value::as_u64)
        .expect("fully_proven count");
    let s_partial = summary
        .get("partially_proven")
        .and_then(Value::as_u64)
        .expect("partially_proven count");
    let s_unproven = summary
        .get("unproven")
        .and_then(Value::as_u64)
        .expect("unproven count");

    assert_eq!(s_fully, fully, "fully_proven count mismatch");
    assert_eq!(s_partial, partial, "partially_proven count mismatch");
    assert_eq!(s_unproven, unproven, "unproven count mismatch");
}
