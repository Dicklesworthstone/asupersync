//! Lean theorem inventory and constructor coverage consistency tests (bd-3n3b2).

use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

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

fn assert_canonicalization_families(
    families: &[Value],
    theorem_names: &BTreeSet<&str>,
    theorem_lines: &BTreeMap<&str, u64>,
) {
    let mut family_ids = BTreeSet::new();
    let mut canonical_theorems = BTreeSet::new();
    let mut variant_theorems = BTreeSet::new();
    for family in families {
        let family_id = family
            .get("family_id")
            .and_then(Value::as_str)
            .expect("family_id must be present");
        assert!(
            family_ids.insert(family_id),
            "family_id appears more than once: {family_id}"
        );
        let canonical = family
            .get("canonical_theorem")
            .and_then(Value::as_str)
            .expect("canonical_theorem must be present");
        assert!(
            theorem_names.contains(canonical),
            "family {family_id} points to unknown canonical theorem: {canonical}"
        );
        assert!(
            canonical_theorems.insert(canonical),
            "canonical theorem appears in multiple families: {canonical}"
        );
        let canonical_line = *theorem_lines
            .get(canonical)
            .expect("canonical theorem line must exist");

        let variants = family
            .get("variants")
            .and_then(Value::as_array)
            .expect("family variants must be an array");
        assert!(
            !variants.is_empty(),
            "family {family_id} must define at least one variant"
        );
        for variant in variants {
            let theorem = variant
                .get("theorem")
                .and_then(Value::as_str)
                .expect("variant theorem must be present");
            let role = variant
                .get("role")
                .and_then(Value::as_str)
                .expect("variant role must be present");
            assert!(
                !role.trim().is_empty(),
                "family {family_id} has variant theorem {theorem} with empty role"
            );
            assert!(
                theorem_names.contains(theorem),
                "family {family_id} variant points to unknown theorem: {theorem}"
            );
            assert_ne!(
                theorem, canonical,
                "family {family_id} variant theorem equals canonical theorem {canonical}"
            );
            assert!(
                variant_theorems.insert(theorem),
                "variant theorem appears in multiple families: {theorem}"
            );
            let variant_line = *theorem_lines
                .get(theorem)
                .expect("variant theorem line must exist");
            assert!(
                canonical_line < variant_line,
                "family {family_id} canonical theorem {canonical} must appear before variant {theorem}"
            );
        }
    }
}

fn assert_layering_rules(
    layering_rules: &[Value],
    theorem_names: &BTreeSet<&str>,
    theorem_lines: &BTreeMap<&str, u64>,
) {
    for rule in layering_rules {
        let rule_id = rule
            .get("rule_id")
            .and_then(Value::as_str)
            .expect("layering rule_id must be present");
        let mut anchor_names = Vec::new();
        let anchors = rule
            .get("anchor_theorems")
            .and_then(Value::as_array)
            .expect("layering anchor_theorems must be an array");
        assert!(
            !anchors.is_empty(),
            "layering rule {rule_id} must include anchor_theorems"
        );
        for anchor in anchors {
            let theorem = anchor
                .as_str()
                .expect("layering anchor theorem names must be strings");
            assert!(
                theorem_names.contains(theorem),
                "layering rule {rule_id} references unknown anchor theorem: {theorem}"
            );
            anchor_names.push(theorem);
        }

        if let Some(disallowed) = rule.get("must_not_depend_on").and_then(Value::as_array) {
            for entry in disallowed {
                let theorem = entry
                    .as_str()
                    .expect("must_not_depend_on theorem names must be strings");
                assert!(
                    theorem_names.contains(theorem),
                    "layering rule {rule_id} references unknown must_not_depend_on theorem: {theorem}"
                );
                let disallowed_line = *theorem_lines
                    .get(theorem)
                    .expect("must_not_depend_on theorem line must exist");
                for anchor in &anchor_names {
                    let anchor_line = *theorem_lines
                        .get(anchor)
                        .expect("anchor theorem line must exist");
                    assert!(
                        anchor_line < disallowed_line,
                        "layering rule {rule_id} requires anchor theorem {anchor} to appear before forbidden dependency target {theorem}"
                    );
                }
            }
        }

        if let Some(required) = rule.get("must_depend_on_any").and_then(Value::as_array) {
            assert!(
                !required.is_empty(),
                "layering rule {rule_id} must_depend_on_any cannot be empty when present"
            );
            for entry in required {
                let theorem = entry
                    .as_str()
                    .expect("must_depend_on_any theorem names must be strings");
                assert!(
                    theorem_names.contains(theorem),
                    "layering rule {rule_id} references unknown must_depend_on_any theorem: {theorem}"
                );
            }
            for anchor in &anchor_names {
                let anchor_line = *theorem_lines
                    .get(anchor)
                    .expect("anchor theorem line must exist");
                let has_prior_requirement = required.iter().any(|entry| {
                    let theorem = entry
                        .as_str()
                        .expect("must_depend_on_any theorem names must be strings");
                    let required_line = *theorem_lines
                        .get(theorem)
                        .expect("must_depend_on_any theorem line must exist");
                    required_line < anchor_line
                });
                assert!(
                    has_prior_requirement,
                    "layering rule {rule_id} requires each anchor theorem to appear after at least one required dependency theorem"
                );
            }
        }
    }
}

#[test]
fn theorem_inventory_canonicalization_metadata_is_consistent() {
    let inventory: Value =
        serde_json::from_str(THEOREM_INVENTORY_JSON).expect("theorem inventory must parse");
    let theorem_entries = inventory
        .get("theorems")
        .and_then(Value::as_array)
        .expect("theorems must be an array");
    let mut theorem_lines = BTreeMap::new();
    for entry in theorem_entries {
        let theorem = entry
            .get("theorem")
            .and_then(Value::as_str)
            .expect("theorem name must be present");
        let line = entry
            .get("line")
            .and_then(Value::as_u64)
            .expect("theorem line must be present");
        assert!(
            theorem_lines.insert(theorem, line).is_none(),
            "duplicate theorem entry in inventory: {theorem}"
        );
    }
    let theorem_names = theorem_lines.keys().copied().collect::<BTreeSet<_>>();

    let canonicalization = inventory
        .get("lemma_canonicalization")
        .expect("lemma_canonicalization metadata must be present");
    let families = canonicalization
        .get("families")
        .and_then(Value::as_array)
        .expect("lemma_canonicalization.families must be an array");
    assert!(
        !families.is_empty(),
        "canonicalization metadata must define at least one family"
    );
    assert_canonicalization_families(families, &theorem_names, &theorem_lines);

    let layering_rules = canonicalization
        .get("layering_rules")
        .and_then(Value::as_array)
        .expect("lemma_canonicalization.layering_rules must be an array");
    assert!(
        !layering_rules.is_empty(),
        "layering_rules must include at least one rule"
    );
    assert_layering_rules(layering_rules, &theorem_names, &theorem_lines);
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
