//! Stale-link detection for theorem-to-rule traceability ledger (bd-1drgu).

use serde_json::Value;
use std::collections::BTreeSet;

const THEOREM_INVENTORY_JSON: &str =
    include_str!("../formal/lean/coverage/theorem_surface_inventory.json");
const STEP_COVERAGE_JSON: &str =
    include_str!("../formal/lean/coverage/step_constructor_coverage.json");
const TRACEABILITY_LEDGER_JSON: &str =
    include_str!("../formal/lean/coverage/theorem_rule_traceability_ledger.json");

#[test]
fn traceability_links_resolve_to_existing_theorems_and_rules() {
    let inventory: Value =
        serde_json::from_str(THEOREM_INVENTORY_JSON).expect("theorem inventory must parse");
    let theorem_lookup = inventory
        .get("theorems")
        .and_then(Value::as_array)
        .expect("theorems must be an array")
        .iter()
        .map(|entry| {
            let theorem = entry
                .get("theorem")
                .and_then(Value::as_str)
                .expect("theorem name must be a string");
            let line = entry
                .get("line")
                .and_then(Value::as_u64)
                .expect("theorem line must be a number");
            (theorem, line)
        })
        .collect::<Vec<_>>();

    let theorem_names = theorem_lookup
        .iter()
        .map(|(name, _)| *name)
        .collect::<BTreeSet<_>>();

    let step_coverage: Value =
        serde_json::from_str(STEP_COVERAGE_JSON).expect("step coverage must parse");
    let rule_ids = step_coverage
        .get("constructors")
        .and_then(Value::as_array)
        .expect("constructors must be an array")
        .iter()
        .map(|entry| {
            let constructor = entry
                .get("constructor")
                .and_then(Value::as_str)
                .expect("constructor must be a string");
            format!("step.{constructor}")
        })
        .collect::<BTreeSet<_>>();

    let ledger: Value =
        serde_json::from_str(TRACEABILITY_LEDGER_JSON).expect("traceability ledger must parse");
    let rows = ledger
        .get("rows")
        .and_then(Value::as_array)
        .expect("rows must be an array");
    assert!(
        !rows.is_empty(),
        "traceability ledger must include at least one row"
    );

    let mut pairs = BTreeSet::new();
    for row in rows {
        let theorem = row
            .get("theorem")
            .and_then(Value::as_str)
            .expect("row theorem must be a string");
        let rule_id = row
            .get("rule_id")
            .and_then(Value::as_str)
            .expect("row rule_id must be a string");
        let line = row
            .get("theorem_line")
            .and_then(Value::as_u64)
            .expect("row theorem_line must be numeric");

        assert!(
            theorem_names.contains(theorem),
            "stale theorem link in ledger: {theorem}"
        );
        assert!(
            rule_ids.contains(rule_id),
            "stale rule link in ledger: {rule_id}"
        );
        let inventory_line = theorem_lookup
            .iter()
            .find_map(|(name, l)| if *name == theorem { Some(*l) } else { None })
            .expect("theorem must exist in inventory");
        assert_eq!(
            line, inventory_line,
            "line drift detected for theorem {theorem}"
        );

        let pair = format!("{rule_id}::{theorem}");
        assert!(
            pairs.insert(pair.clone()),
            "duplicate rule/theorem pair in ledger: {pair}"
        );
    }
}

#[test]
fn progress_and_canonical_ladder_rules_are_trace_linked() {
    let ledger: Value =
        serde_json::from_str(TRACEABILITY_LEDGER_JSON).expect("traceability ledger must parse");
    let rows = ledger
        .get("rows")
        .and_then(Value::as_array)
        .expect("rows must be an array");

    let mut rule_to_theorems = std::collections::BTreeMap::<String, BTreeSet<String>>::new();
    for row in rows {
        let rule_id = row
            .get("rule_id")
            .and_then(Value::as_str)
            .expect("row rule_id must be a string")
            .to_string();
        let theorem = row
            .get("theorem")
            .and_then(Value::as_str)
            .expect("row theorem must be a string")
            .to_string();
        rule_to_theorems.entry(rule_id).or_default().insert(theorem);
    }

    let required_rule_theorem_pairs = [
        ("step.cancelMasked", "cancel_masked_step"),
        ("step.cancelAcknowledge", "cancel_ack_step"),
        ("step.cancelFinalize", "cancel_finalize_step"),
        ("step.cancelComplete", "cancel_complete_step"),
        ("step.closeBegin", "close_begin_step"),
        ("step.closeCancelChildren", "close_cancel_children_step"),
        ("step.closeChildrenDone", "close_children_done_step"),
        ("step.closeRunFinalizer", "close_run_finalizer_step"),
        ("step.close", "close_complete_step"),
        ("step.reserve", "reserve_creates_reserved"),
        ("step.commit", "commit_resolves"),
        ("step.abort", "abort_resolves"),
        ("step.leak", "leak_marks_leaked"),
    ];

    for (rule, theorem) in required_rule_theorem_pairs {
        let mapped = rule_to_theorems
            .get(rule)
            .unwrap_or_else(|| panic!("missing rule in traceability ledger: {rule}"));
        assert!(
            mapped.contains(theorem),
            "traceability ledger missing required theorem {theorem} for rule {rule}"
        );
    }
}
