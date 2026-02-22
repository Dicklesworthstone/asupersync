//! Invariant-to-theorem and invariant-to-test link map checks (bd-2iwok).

use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

const LINK_MAP_JSON: &str =
    include_str!("../formal/lean/coverage/invariant_theorem_test_link_map.json");
const INVARIANT_JSON: &str =
    include_str!("../formal/lean/coverage/invariant_status_inventory.json");
const THEOREM_JSON: &str = include_str!("../formal/lean/coverage/theorem_surface_inventory.json");
const TRACEABILITY_JSON: &str =
    include_str!("../formal/lean/coverage/theorem_rule_traceability_ledger.json");
const RUNTIME_MAP_JSON: &str =
    include_str!("../formal/lean/coverage/runtime_state_refinement_map.json");
const BEADS_JSONL: &str = include_str!("../.beads/issues.jsonl");

#[derive(Debug)]
struct InvariantExpectations {
    name: String,
    lean_status: String,
    theorem_names: BTreeSet<String>,
    test_refs: BTreeSet<String>,
    gap_count: usize,
}

#[derive(Debug, Clone, Copy)]
struct SummaryCounts {
    invariants_total: usize,
    invariants_with_theorem_witnesses: usize,
    invariants_with_executable_checks: usize,
    invariants_with_explicit_gaps: usize,
    invariants_meeting_theorem_and_check_requirement: usize,
    gap_entries_total: usize,
}

fn parse_json(input: &str, label: &str) -> Value {
    serde_json::from_str(input).unwrap_or_else(|_| panic!("{label} must parse"))
}

fn bead_ids() -> BTreeSet<String> {
    BEADS_JSONL
        .lines()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .flat_map(|entry| {
            let mut ids = Vec::new();
            if let Some(id) = entry.get("id").and_then(Value::as_str) {
                ids.push(id.to_string());
            }
            if let Some(external_ref) = entry.get("external_ref").and_then(Value::as_str) {
                if !external_ref.trim().is_empty() {
                    ids.push(external_ref.to_string());
                }
            }
            ids
        })
        .collect::<BTreeSet<_>>()
}

fn theorem_lines(theorem_inventory: &Value) -> BTreeMap<String, u64> {
    theorem_inventory
        .get("theorems")
        .and_then(Value::as_array)
        .expect("theorems must be an array")
        .iter()
        .map(|entry| {
            (
                entry
                    .get("theorem")
                    .and_then(Value::as_str)
                    .expect("theorem must be a string")
                    .to_string(),
                entry
                    .get("line")
                    .and_then(Value::as_u64)
                    .expect("line must be numeric"),
            )
        })
        .collect::<BTreeMap<_, _>>()
}

fn theorem_rule_ids(traceability_ledger: &Value) -> BTreeMap<String, BTreeSet<String>> {
    let mut map = BTreeMap::<String, BTreeSet<String>>::new();
    for row in traceability_ledger
        .get("rows")
        .and_then(Value::as_array)
        .expect("rows must be an array")
    {
        let theorem = row
            .get("theorem")
            .and_then(Value::as_str)
            .expect("row theorem must be a string");
        let rule_id = row
            .get("rule_id")
            .and_then(Value::as_str)
            .expect("row rule_id must be a string");
        map.entry(theorem.to_string())
            .or_default()
            .insert(rule_id.to_string());
    }
    map
}

fn invariant_expectations(invariant_inventory: &Value) -> BTreeMap<String, InvariantExpectations> {
    invariant_inventory
        .get("invariants")
        .and_then(Value::as_array)
        .expect("invariants must be an array")
        .iter()
        .map(|entry| {
            let id = entry
                .get("id")
                .and_then(Value::as_str)
                .expect("invariant id must be string")
                .to_string();
            let name = entry
                .get("name")
                .and_then(Value::as_str)
                .expect("invariant name must be string")
                .to_string();
            let lean_status = entry
                .get("lean_status")
                .and_then(Value::as_str)
                .expect("lean_status must be string")
                .to_string();
            let theorem_names = entry
                .get("lean_theorems")
                .and_then(Value::as_array)
                .expect("lean_theorems must be array")
                .iter()
                .map(|v| {
                    v.as_str()
                        .expect("lean_theorems entries must be strings")
                        .to_string()
                })
                .collect::<BTreeSet<_>>();
            let test_refs = entry
                .get("test_refs")
                .and_then(Value::as_array)
                .expect("test_refs must be array")
                .iter()
                .map(|v| {
                    v.as_str()
                        .expect("test_refs entries must be strings")
                        .to_string()
                })
                .collect::<BTreeSet<_>>();
            let gap_count = entry
                .get("gaps")
                .and_then(Value::as_array)
                .expect("gaps must be array")
                .len();

            (
                id,
                InvariantExpectations {
                    name,
                    lean_status,
                    theorem_names,
                    test_refs,
                    gap_count,
                },
            )
        })
        .collect::<BTreeMap<_, _>>()
}

fn link_rows(link_map: &Value) -> &[Value] {
    link_map
        .get("invariant_links")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .expect("invariant_links must be an array")
}

fn assert_link_map_header(link_map: &Value) {
    assert_eq!(
        link_map
            .get("schema_version")
            .and_then(Value::as_str)
            .expect("schema_version must be string"),
        "1.0.0"
    );
    assert_eq!(
        link_map
            .get("link_map_id")
            .and_then(Value::as_str)
            .expect("link_map_id must be string"),
        "lean.invariant_theorem_test_link_map.v1"
    );
    let generated_by = link_map
        .get("generated_by")
        .and_then(Value::as_str)
        .expect("generated_by must be string");
    assert!(
        !generated_by.trim().is_empty(),
        "generated_by must be non-empty"
    );

    let generated_at = link_map
        .get("generated_at")
        .and_then(Value::as_str)
        .expect("generated_at must be string");
    assert!(
        generated_at.contains('T') && generated_at.ends_with('Z'),
        "generated_at must be UTC RFC3339 (Z suffix)"
    );

    let source_artifacts = link_map
        .get("source_artifacts")
        .and_then(Value::as_object)
        .expect("source_artifacts must be an object");
    for required in [
        "invariant_status_inventory",
        "theorem_surface_inventory",
        "theorem_rule_traceability_ledger",
    ] {
        let artifact = source_artifacts
            .get(required)
            .and_then(Value::as_str)
            .unwrap_or_else(|| panic!("source_artifacts.{required} must be string"));
        assert!(
            Path::new(artifact).exists(),
            "source_artifact path must exist: {artifact}"
        );
    }
}

fn assert_witnesses(
    invariant_id: &str,
    row: &Value,
    expectations: &InvariantExpectations,
    theorem_lines: &BTreeMap<String, u64>,
    theorem_rule_ids: &BTreeMap<String, BTreeSet<String>>,
) -> bool {
    let witness_rows = row
        .get("theorem_witnesses")
        .and_then(Value::as_array)
        .expect("theorem_witnesses must be an array");
    let witness_names = witness_rows
        .iter()
        .map(|entry| {
            entry
                .get("theorem")
                .and_then(Value::as_str)
                .expect("witness theorem must be a string")
                .to_string()
        })
        .collect::<BTreeSet<_>>();
    assert_eq!(
        witness_names, expectations.theorem_names,
        "theorem witness set mismatch for {invariant_id}"
    );

    for witness in witness_rows {
        let theorem = witness
            .get("theorem")
            .and_then(Value::as_str)
            .expect("witness theorem must be a string");
        let line = witness
            .get("theorem_line")
            .and_then(Value::as_u64)
            .expect("witness theorem_line must be numeric");
        let expected_line = theorem_lines
            .get(theorem)
            .unwrap_or_else(|| panic!("theorem witness {theorem} missing from theorem inventory"));
        assert_eq!(
            line, *expected_line,
            "theorem line mismatch for witness {theorem}"
        );

        let rule_ids = witness
            .get("rule_ids")
            .and_then(Value::as_array)
            .expect("rule_ids must be an array")
            .iter()
            .map(|entry| {
                entry
                    .as_str()
                    .expect("rule_ids entries must be strings")
                    .to_string()
            })
            .collect::<Vec<_>>();

        let mut sorted_rule_ids = rule_ids.clone();
        sorted_rule_ids.sort();
        sorted_rule_ids.dedup();
        assert_eq!(
            rule_ids, sorted_rule_ids,
            "rule_ids for theorem {theorem} must be sorted and deduplicated"
        );

        let expected_rules = theorem_rule_ids
            .get(theorem)
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .collect::<Vec<_>>();
        assert_eq!(
            rule_ids, expected_rules,
            "rule linkage mismatch for theorem {theorem}"
        );
    }

    !witness_rows.is_empty()
}

fn assert_checks(invariant_id: &str, row: &Value, expectations: &InvariantExpectations) -> bool {
    let checks = row
        .get("executable_checks")
        .and_then(Value::as_array)
        .expect("executable_checks must be an array")
        .iter()
        .map(|entry| {
            entry
                .as_str()
                .expect("executable_checks entries must be strings")
                .to_string()
        })
        .collect::<BTreeSet<_>>();
    assert_eq!(
        checks, expectations.test_refs,
        "executable check set mismatch for {invariant_id}"
    );
    for check in &checks {
        assert!(
            Path::new(check).exists(),
            "missing executable check path in link map: {check}"
        );
    }

    !checks.is_empty()
}

fn assert_gaps(
    invariant_id: &str,
    row: &Value,
    expectations: &InvariantExpectations,
    bead_ids: &BTreeSet<String>,
    requires_explicit_gap: bool,
) {
    let explicit_gaps = row
        .get("explicit_gaps")
        .and_then(Value::as_array)
        .expect("explicit_gaps must be an array");

    if requires_explicit_gap {
        assert!(
            !explicit_gaps.is_empty(),
            "invariant {invariant_id} must declare explicit gaps when theorem/check witnesses are incomplete"
        );
    }
    if expectations.gap_count > 0 {
        assert!(
            !explicit_gaps.is_empty(),
            "invariant {invariant_id} has inventory gaps but no explicit link-map gaps"
        );
    }

    for gap in explicit_gaps {
        let gap_id = gap
            .get("gap_id")
            .and_then(Value::as_str)
            .expect("gap_id must be a string");
        assert!(!gap_id.is_empty(), "gap_id must be non-empty");
        assert!(
            gap.get("description")
                .and_then(Value::as_str)
                .is_some_and(|description| !description.trim().is_empty()),
            "gap description must be non-empty for {invariant_id}::{gap_id}"
        );
        assert!(
            gap.get("owner")
                .and_then(Value::as_str)
                .is_some_and(|owner| !owner.trim().is_empty()),
            "gap owner must be non-empty for {invariant_id}::{gap_id}"
        );

        let blockers = gap
            .get("dependency_blockers")
            .and_then(Value::as_array)
            .expect("dependency_blockers must be an array");
        assert!(
            !blockers.is_empty(),
            "gap {invariant_id}::{gap_id} must define dependency blockers"
        );
        for blocker in blockers {
            let blocker_id = blocker
                .as_str()
                .expect("dependency_blockers entries must be strings");
            assert!(
                bead_ids.contains(blocker_id),
                "gap {invariant_id}::{gap_id} references unknown bead {blocker_id}"
            );
        }
    }
}

fn assert_status_and_assumption_metadata(
    invariant_id: &str,
    row: &Value,
    expectations: &InvariantExpectations,
) {
    let proof_status = row
        .get("proof_status")
        .and_then(Value::as_str)
        .expect("proof_status must be a string");
    assert_eq!(
        proof_status, expectations.lean_status,
        "proof_status drift for {invariant_id}"
    );

    let assumption_envelope = row
        .get("assumption_envelope")
        .expect("assumption_envelope must be present");
    assert!(
        assumption_envelope
            .get("assumption_id")
            .and_then(Value::as_str)
            .is_some_and(|id| !id.trim().is_empty()),
        "{invariant_id} assumption_envelope.assumption_id must be non-empty"
    );
    let assumptions = assumption_envelope
        .get("assumptions")
        .and_then(Value::as_array)
        .expect("assumption_envelope.assumptions must be an array");
    assert!(
        !assumptions.is_empty(),
        "{invariant_id} must define at least one assumption"
    );
    let runtime_guardrails = assumption_envelope
        .get("runtime_guardrails")
        .and_then(Value::as_array)
        .expect("assumption_envelope.runtime_guardrails must be an array");
    assert!(
        !runtime_guardrails.is_empty(),
        "{invariant_id} must define runtime_guardrails"
    );

    let composition_contract = row
        .get("composition_contract")
        .expect("composition_contract must be present");
    let status = composition_contract
        .get("status")
        .and_then(Value::as_str)
        .expect("composition_contract.status must be a string");
    assert!(
        ["ready", "partial", "planned"].contains(&status),
        "{invariant_id} composition_contract.status must be one of ready|partial|planned"
    );
    let consumed_by = composition_contract
        .get("consumed_by")
        .and_then(Value::as_array)
        .expect("composition_contract.consumed_by must be an array");
    assert!(
        !consumed_by.is_empty(),
        "{invariant_id} composition_contract.consumed_by must be non-empty"
    );
    for consumer in consumed_by {
        let consumer = consumer
            .as_str()
            .expect("composition_contract.consumed_by entries must be strings");
        assert!(
            Path::new(consumer).exists(),
            "{invariant_id} composition consumer path missing: {consumer}"
        );
    }
    let feeds = composition_contract
        .get("feeds_invariants")
        .and_then(Value::as_array)
        .expect("composition_contract.feeds_invariants must be an array");
    assert!(
        !feeds.is_empty(),
        "{invariant_id} composition_contract.feeds_invariants must be non-empty"
    );
}

fn summary_counts(rows: &[Value]) -> SummaryCounts {
    let invariants_total = rows.len();
    let invariants_with_theorem_witnesses = rows
        .iter()
        .filter(|row| {
            row.get("theorem_witnesses")
                .and_then(Value::as_array)
                .is_some_and(|witnesses| !witnesses.is_empty())
        })
        .count();
    let invariants_with_executable_checks = rows
        .iter()
        .filter(|row| {
            row.get("executable_checks")
                .and_then(Value::as_array)
                .is_some_and(|checks| !checks.is_empty())
        })
        .count();
    let invariants_with_explicit_gaps = rows
        .iter()
        .filter(|row| {
            row.get("explicit_gaps")
                .and_then(Value::as_array)
                .is_some_and(|gaps| !gaps.is_empty())
        })
        .count();
    let invariants_meeting_theorem_and_check_requirement = rows
        .iter()
        .filter(|row| {
            row.get("theorem_witnesses")
                .and_then(Value::as_array)
                .is_some_and(|witnesses| !witnesses.is_empty())
                && row
                    .get("executable_checks")
                    .and_then(Value::as_array)
                    .is_some_and(|checks| !checks.is_empty())
        })
        .count();
    let gap_entries_total = rows
        .iter()
        .map(|row| {
            row.get("explicit_gaps")
                .and_then(Value::as_array)
                .expect("explicit_gaps must be array")
                .len()
        })
        .sum::<usize>();

    SummaryCounts {
        invariants_total,
        invariants_with_theorem_witnesses,
        invariants_with_executable_checks,
        invariants_with_explicit_gaps,
        invariants_meeting_theorem_and_check_requirement,
        gap_entries_total,
    }
}

fn assert_summary_matches(summary: &Value, counts: SummaryCounts) {
    assert_eq!(
        summary
            .get("invariants_total")
            .and_then(Value::as_u64)
            .expect("summary.invariants_total must be numeric") as usize,
        counts.invariants_total
    );
    assert_eq!(
        summary
            .get("invariants_with_theorem_witnesses")
            .and_then(Value::as_u64)
            .expect("summary.invariants_with_theorem_witnesses must be numeric") as usize,
        counts.invariants_with_theorem_witnesses
    );
    assert_eq!(
        summary
            .get("invariants_with_executable_checks")
            .and_then(Value::as_u64)
            .expect("summary.invariants_with_executable_checks must be numeric") as usize,
        counts.invariants_with_executable_checks
    );
    assert_eq!(
        summary
            .get("invariants_with_explicit_gaps")
            .and_then(Value::as_u64)
            .expect("summary.invariants_with_explicit_gaps must be numeric") as usize,
        counts.invariants_with_explicit_gaps
    );
    assert_eq!(
        summary
            .get("invariants_meeting_theorem_and_check_requirement")
            .and_then(Value::as_u64)
            .expect("summary.invariants_meeting_theorem_and_check_requirement must be numeric")
            as usize,
        counts.invariants_meeting_theorem_and_check_requirement
    );
    assert_eq!(
        summary
            .get("invariants_covered_via_explicit_gap_only")
            .and_then(Value::as_u64)
            .expect("summary.invariants_covered_via_explicit_gap_only must be numeric")
            as usize,
        counts
            .invariants_total
            .saturating_sub(counts.invariants_meeting_theorem_and_check_requirement)
    );
    assert_eq!(
        summary
            .get("gap_entries_total")
            .and_then(Value::as_u64)
            .expect("summary.gap_entries_total must be numeric") as usize,
        counts.gap_entries_total
    );
}

#[test]
fn link_map_rows_cover_all_invariants_and_resolve_sources() {
    let link_map = parse_json(LINK_MAP_JSON, "link map");
    let invariant_inventory = parse_json(INVARIANT_JSON, "invariant inventory");
    let theorem_inventory = parse_json(THEOREM_JSON, "theorem inventory");
    let traceability_ledger = parse_json(TRACEABILITY_JSON, "traceability ledger");

    assert_link_map_header(&link_map);

    let theorem_lines = theorem_lines(&theorem_inventory);
    let theorem_rule_ids = theorem_rule_ids(&traceability_ledger);
    let expectations = invariant_expectations(&invariant_inventory);
    let bead_ids = bead_ids();
    let rows = link_rows(&link_map);

    assert_eq!(
        rows.len(),
        expectations.len(),
        "link map must include one row per invariant"
    );

    let mut seen_invariants = BTreeSet::new();
    for row in rows {
        let invariant_id = row
            .get("invariant_id")
            .and_then(Value::as_str)
            .expect("invariant_id must be a string");
        assert!(
            seen_invariants.insert(invariant_id.to_string()),
            "duplicate invariant link row for {invariant_id}"
        );

        let expectations = expectations
            .get(invariant_id)
            .unwrap_or_else(|| panic!("link map references unknown invariant id: {invariant_id}"));

        assert_eq!(
            row.get("invariant_name")
                .and_then(Value::as_str)
                .expect("invariant_name must be a string"),
            expectations.name,
            "invariant_name drift for {invariant_id}"
        );
        assert_status_and_assumption_metadata(invariant_id, row, expectations);

        let has_theorem_witnesses = assert_witnesses(
            invariant_id,
            row,
            expectations,
            &theorem_lines,
            &theorem_rule_ids,
        );
        let has_executable_checks = assert_checks(invariant_id, row, expectations);
        assert_gaps(
            invariant_id,
            row,
            expectations,
            &bead_ids,
            !has_theorem_witnesses || !has_executable_checks,
        );
    }

    let expected_ids = expectations.keys().cloned().collect::<BTreeSet<_>>();
    assert_eq!(
        seen_invariants, expected_ids,
        "link-map invariant coverage does not match invariant inventory"
    );
}

#[test]
fn link_map_summary_counts_match_rows() {
    let link_map = parse_json(LINK_MAP_JSON, "link map");
    let rows = link_rows(&link_map);
    let counts = summary_counts(rows);
    let summary = link_map
        .get("summary")
        .expect("summary object must be present");
    assert_summary_matches(summary, counts);
}

fn invariant_row<'a>(rows: &'a [Value], invariant_id: &str) -> &'a Value {
    rows.iter()
        .find(|row| row.get("invariant_id").and_then(Value::as_str) == Some(invariant_id))
        .unwrap_or_else(|| panic!("missing {invariant_id} row"))
}

fn theorem_witness_names(row: &Value) -> BTreeSet<String> {
    row.get("theorem_witnesses")
        .and_then(Value::as_array)
        .expect("theorem_witnesses must be an array")
        .iter()
        .map(|entry| {
            entry
                .get("theorem")
                .and_then(Value::as_str)
                .expect("theorem witness name must be string")
                .to_string()
        })
        .collect::<BTreeSet<_>>()
}

fn assert_liveness_contract(
    row: &Value,
    invariant_id: &str,
    expected_status: &str,
    expected_consumers: &[&str],
) {
    let assumption_envelope = row
        .get("assumption_envelope")
        .expect("liveness rows must define assumption_envelope");
    assert!(
        assumption_envelope
            .get("assumption_id")
            .and_then(Value::as_str)
            .is_some_and(|id| !id.trim().is_empty()),
        "{invariant_id} assumption_envelope.assumption_id must be non-empty"
    );
    let assumptions = assumption_envelope
        .get("assumptions")
        .and_then(Value::as_array)
        .expect("assumption_envelope.assumptions must be an array");
    assert!(
        !assumptions.is_empty(),
        "{invariant_id} must provide at least one liveness assumption"
    );
    let runtime_guardrails = assumption_envelope
        .get("runtime_guardrails")
        .and_then(Value::as_array)
        .expect("assumption_envelope.runtime_guardrails must be an array");
    assert!(
        !runtime_guardrails.is_empty(),
        "{invariant_id} must provide runtime guardrails"
    );

    let composition_contract = row
        .get("composition_contract")
        .expect("liveness rows must define composition_contract");
    assert_eq!(
        composition_contract
            .get("status")
            .and_then(Value::as_str)
            .expect("composition_contract.status must be a string"),
        expected_status,
        "{invariant_id} composition_contract.status mismatch"
    );

    let consumed_by = composition_contract
        .get("consumed_by")
        .and_then(Value::as_array)
        .expect("composition_contract.consumed_by must be an array")
        .iter()
        .map(|entry| {
            entry
                .as_str()
                .expect("consumed_by entries must be strings")
                .to_string()
        })
        .collect::<BTreeSet<_>>();
    for consumer in expected_consumers {
        assert!(
            consumed_by.contains(*consumer),
            "{invariant_id} composition_contract missing consumer {consumer}"
        );
        assert!(
            Path::new(consumer).exists(),
            "{invariant_id} composition consumer path missing: {consumer}"
        );
    }
}

fn assert_cancel_liveness_row(cancel_row: &Value) {
    let cancel_theorems = theorem_witness_names(cancel_row);
    for theorem in [
        "cancel_protocol_terminates",
        "cancel_steps_testable_bound",
        "cancel_propagation_bounded",
    ] {
        assert!(
            cancel_theorems.contains(theorem),
            "cancel liveness witness missing theorem {theorem}"
        );
    }
    assert_liveness_contract(
        cancel_row,
        "inv.cancel.protocol",
        "ready",
        &[
            "tests/refinement_conformance.rs",
            "tests/cancellation_conformance.rs",
        ],
    );
    let cancel_gaps = cancel_row
        .get("explicit_gaps")
        .and_then(Value::as_array)
        .expect("cancel explicit_gaps must be an array");
    let cancel_idempotence_gap = cancel_gaps
        .iter()
        .find(|gap| {
            gap.get("gap_id").and_then(Value::as_str)
                == Some("inv.cancel.protocol.gap.idempotence-theorem-missing")
        })
        .expect("cancel idempotence gap must be tracked explicitly");
    let cancel_owner = cancel_idempotence_gap
        .get("owner")
        .and_then(Value::as_str)
        .expect("cancel idempotence gap owner must be present");
    assert!(
        cancel_owner != "unassigned",
        "cancel idempotence gap owner must be explicitly assigned"
    );
}

fn assert_quiescence_liveness_row(quiescence_row: &Value) {
    let quiescence_theorems = theorem_witness_names(quiescence_row);
    for theorem in ["close_implies_quiescent", "close_quiescence_decomposition"] {
        assert!(
            quiescence_theorems.contains(theorem),
            "region-close liveness witness missing theorem {theorem}"
        );
    }
    let quiescence_gaps = quiescence_row
        .get("explicit_gaps")
        .and_then(Value::as_array)
        .expect("quiescence explicit_gaps must be an array");
    assert!(
        quiescence_gaps.is_empty(),
        "inv.region_close.quiescence should have no explicit gaps"
    );
    assert_liveness_contract(
        quiescence_row,
        "inv.region_close.quiescence",
        "ready",
        &[
            "tests/refinement_conformance.rs",
            "tests/region_lifecycle_conformance.rs",
        ],
    );
}

fn assert_loser_drain_liveness_row(losers_row: &Value) {
    let loser_checks = losers_row
        .get("executable_checks")
        .and_then(Value::as_array)
        .expect("loser-drain executable_checks must be an array");
    assert!(
        !loser_checks.is_empty(),
        "inv.race.losers_drained must keep executable checks"
    );
    assert_liveness_contract(
        losers_row,
        "inv.race.losers_drained",
        "partial",
        &[
            "tests/runtime_e2e.rs",
            "tests/refinement_conformance.rs",
            "tests/e2e/combinator/cancel_correctness/loser_drain.rs",
        ],
    );
    let loser_gaps = losers_row
        .get("explicit_gaps")
        .and_then(Value::as_array)
        .expect("loser-drain explicit_gaps must be an array");
    let direct_gap = loser_gaps
        .iter()
        .find(|gap| {
            gap.get("gap_id").and_then(Value::as_str)
                == Some("inv.race.losers_drained.gap.direct-lean-theorem-missing")
        })
        .expect("loser-drain direct Lean theorem gap must be tracked explicitly");
    let dependency_blockers = direct_gap
        .get("dependency_blockers")
        .and_then(Value::as_array)
        .expect("loser-drain gap dependency_blockers must be an array")
        .iter()
        .map(|entry| {
            entry
                .as_str()
                .expect("dependency_blockers entries must be strings")
        })
        .collect::<BTreeSet<_>>();
    assert!(
        dependency_blockers.contains("bd-19efq"),
        "loser-drain gap must be blocked by bd-19efq until direct theorem lands"
    );
    let owner = direct_gap
        .get("owner")
        .and_then(Value::as_str)
        .expect("loser-drain gap owner must be present");
    assert!(
        owner != "unassigned",
        "loser-drain gap owner must be explicitly assigned"
    );
}

fn assert_obligation_terminal_outcomes_row(obligation_row: &Value) {
    let obligation_theorems = theorem_witness_names(obligation_row);
    for theorem in [
        "commit_resolves",
        "abort_resolves",
        "leak_marks_leaked",
        "commit_removes_from_ledger",
        "abort_removes_from_ledger",
        "leak_removes_from_ledger",
        "committed_obligation_stable",
        "aborted_obligation_stable",
        "leaked_obligation_stable",
        "obligation_in_ledger_blocks_close",
        "close_implies_ledger_empty",
        "call_obligation_resolved_at_close",
        "no_reserved_call_obligations_after_close",
        "registry_lease_resolved_at_close",
    ] {
        assert!(
            obligation_theorems.contains(theorem),
            "obligation witness missing terminal-outcome theorem {theorem}"
        );
    }

    assert_liveness_contract(
        obligation_row,
        "inv.obligation.no_leaks",
        "partial",
        &[
            "tests/obligation_lifecycle_e2e.rs",
            "tests/cancel_obligation_invariants.rs",
            "tests/leak_regression_e2e.rs",
            "tests/lease_semantics.rs",
        ],
    );

    let obligation_gaps = obligation_row
        .get("explicit_gaps")
        .and_then(Value::as_array)
        .expect("obligation explicit_gaps must be an array");
    let global_zero_gap = obligation_gaps
        .iter()
        .find(|gap| {
            gap.get("gap_id").and_then(Value::as_str)
                == Some("inv.obligation.no_leaks.gap.global-zero-leak-theorem-missing")
        })
        .expect("obligation global-zero-leak gap must be tracked explicitly");

    let dependency_blockers = global_zero_gap
        .get("dependency_blockers")
        .and_then(Value::as_array)
        .expect("obligation gap dependency_blockers must be an array")
        .iter()
        .map(|entry| {
            entry
                .as_str()
                .expect("dependency_blockers entries must be strings")
        })
        .collect::<BTreeSet<_>>();
    assert!(
        dependency_blockers.contains("asupersync-1pdet"),
        "obligation gap must include asupersync-1pdet as closure path"
    );
    assert!(
        dependency_blockers.contains("bd-3k6l5"),
        "obligation gap must retain bd-3k6l5 dependency"
    );

    let owner = global_zero_gap
        .get("owner")
        .and_then(Value::as_str)
        .expect("obligation gap owner must be present");
    assert!(
        owner != "unassigned",
        "obligation gap owner must be explicitly assigned"
    );
}

#[test]
fn liveness_invariants_have_termination_quiescence_and_gap_contracts() {
    let link_map = parse_json(LINK_MAP_JSON, "link map");
    let rows = link_rows(&link_map);
    assert_cancel_liveness_row(invariant_row(rows, "inv.cancel.protocol"));
    assert_quiescence_liveness_row(invariant_row(rows, "inv.region_close.quiescence"));
    assert_loser_drain_liveness_row(invariant_row(rows, "inv.race.losers_drained"));
}

#[test]
fn obligation_invariant_tracks_terminal_outcomes_and_gap_contracts() {
    let link_map = parse_json(LINK_MAP_JSON, "link map");
    let rows = link_rows(&link_map);
    assert_obligation_terminal_outcomes_row(invariant_row(rows, "inv.obligation.no_leaks"));
}

fn assert_class_row<'a>(
    row: &'a Value,
    class: &str,
    invariant_ids: &BTreeSet<String>,
    cadence_ids: &BTreeSet<String>,
) -> &'a str {
    let linked_invariants = row
        .get("invariant_ids")
        .and_then(Value::as_array)
        .expect("invariant_ids must be an array");
    assert!(
        !linked_invariants.is_empty(),
        "{class} must link to at least one invariant_id"
    );
    for invariant in linked_invariants {
        let invariant = invariant
            .as_str()
            .expect("invariant_ids entries must be strings");
        assert!(
            invariant_ids.contains(invariant),
            "{class} references unknown invariant_id {invariant}"
        );
    }

    let checklist_ids = row
        .get("checklist_ids")
        .and_then(Value::as_array)
        .expect("checklist_ids must be an array");
    assert!(
        !checklist_ids.is_empty(),
        "{class} must define checklist_ids"
    );

    let conformance_artifacts = row
        .get("conformance_artifacts")
        .and_then(Value::as_array)
        .expect("conformance_artifacts must be an array");
    assert!(
        !conformance_artifacts.is_empty(),
        "{class} must define conformance_artifacts"
    );
    for artifact in conformance_artifacts {
        let artifact = artifact
            .as_str()
            .expect("conformance_artifacts entries must be strings");
        assert!(
            Path::new(artifact).exists(),
            "{class} conformance artifact path missing: {artifact}"
        );
    }

    let governance_cadence_ids = row
        .get("governance_cadence_ids")
        .and_then(Value::as_array)
        .expect("governance_cadence_ids must be an array");
    assert!(
        !governance_cadence_ids.is_empty(),
        "{class} must define governance_cadence_ids"
    );
    for cadence in governance_cadence_ids {
        let cadence = cadence
            .as_str()
            .expect("governance_cadence_ids entries must be strings");
        assert!(
            cadence_ids.contains(cadence),
            "{class} references unknown governance cadence_id {cadence}"
        );
    }

    let failure_policy = row
        .get("failure_policy")
        .and_then(Value::as_str)
        .expect("failure_policy must be a string");
    assert!(
        matches!(failure_policy, "fail-fast" | "fail-safe"),
        "{class} failure_policy must be fail-fast or fail-safe"
    );
    assert!(
        row.get("policy_rationale")
            .and_then(Value::as_str)
            .is_some_and(|text| !text.trim().is_empty()),
        "{class} must define non-empty policy_rationale"
    );
    failure_policy
}

fn assert_assumption_class_matrix(
    contract: &Value,
    required_classes: &BTreeSet<&str>,
    invariant_ids: &BTreeSet<String>,
    cadence_ids: &BTreeSet<String>,
) {
    let class_rows = contract
        .get("assumption_class_matrix")
        .and_then(Value::as_array)
        .expect("assumption_class_matrix must be an array");
    let mut seen_classes = BTreeSet::new();
    let mut seen_policies = BTreeSet::new();
    for row in class_rows {
        let class = row
            .get("assumption_class")
            .and_then(Value::as_str)
            .expect("assumption_class must be a string");
        assert!(
            seen_classes.insert(class),
            "assumption_class_matrix must not repeat class {class}"
        );
        assert!(
            required_classes.contains(class),
            "assumption_class_matrix references undeclared class {class}"
        );
        let failure_policy = assert_class_row(row, class, invariant_ids, cadence_ids);
        seen_policies.insert(failure_policy);
    }
    assert_eq!(
        seen_classes.len(),
        required_classes.len(),
        "assumption_class_matrix must cover all required assumption classes"
    );
    assert_eq!(
        seen_policies,
        BTreeSet::from(["fail-fast", "fail-safe"]),
        "matrix must encode both fail-fast and fail-safe policies"
    );
}

fn assert_incident_triage_flow(contract: &Value) {
    let expected_steps = BTreeSet::from([
        "classify_assumption",
        "verify_guardrails",
        "route_disposition",
        "governance_escalation",
    ]);
    let mut seen_steps = BTreeSet::new();
    for step in contract
        .get("incident_triage_flow")
        .and_then(Value::as_array)
        .expect("incident_triage_flow must be an array")
    {
        let step_id = step
            .get("step_id")
            .and_then(Value::as_str)
            .expect("incident_triage_flow.step_id must be a string");
        assert!(
            seen_steps.insert(step_id),
            "incident_triage_flow must not repeat step_id {step_id}"
        );
        assert!(
            expected_steps.contains(step_id),
            "incident_triage_flow contains unknown step_id {step_id}"
        );
        assert!(
            step.get("description")
                .and_then(Value::as_str)
                .is_some_and(|value| !value.trim().is_empty()),
            "incident_triage_flow.{step_id}.description must be non-empty"
        );
        let required_outputs = step
            .get("required_outputs")
            .and_then(Value::as_array)
            .expect("incident_triage_flow.required_outputs must be an array");
        assert!(
            !required_outputs.is_empty(),
            "incident_triage_flow.{step_id} must define required_outputs"
        );
    }
    assert_eq!(
        seen_steps, expected_steps,
        "incident_triage_flow must include all required step_ids"
    );
}

#[test]
fn reliability_hardening_contract_covers_assumption_classes_and_governance_flow() {
    let link_map = parse_json(LINK_MAP_JSON, "link map");
    let runtime_map = parse_json(RUNTIME_MAP_JSON, "runtime_state_refinement_map");

    let contract = link_map
        .get("reliability_hardening_contract")
        .expect("reliability_hardening_contract must exist");
    assert_eq!(
        contract
            .get("contract_id")
            .and_then(Value::as_str)
            .expect("contract_id must be a string"),
        "lean.track6.reliability_hardening.v1"
    );
    assert_eq!(
        contract
            .get("source_bead")
            .and_then(Value::as_str)
            .expect("source_bead must be a string"),
        "asupersync-2izu4"
    );

    let required_classes = contract
        .get("classification_policy")
        .and_then(|policy| policy.get("required_assumption_classes"))
        .and_then(Value::as_array)
        .expect("classification_policy.required_assumption_classes must be an array")
        .iter()
        .map(|entry| {
            entry
                .as_str()
                .expect("required_assumption_classes entries must be strings")
        })
        .collect::<BTreeSet<_>>();
    assert_eq!(
        required_classes,
        BTreeSet::from([
            "budget_constraints",
            "cancellation_protocol",
            "region_lifecycle",
            "obligation_resolution",
        ])
    );

    let severity_levels = contract
        .get("classification_policy")
        .and_then(|policy| policy.get("incident_severity_levels"))
        .and_then(Value::as_array)
        .expect("classification_policy.incident_severity_levels must be an array")
        .iter()
        .map(|entry| {
            entry
                .as_str()
                .expect("incident_severity_levels entries must be strings")
        })
        .collect::<BTreeSet<_>>();
    assert_eq!(severity_levels, BTreeSet::from(["sev1", "sev2", "sev3"]));

    let cadence_ids = runtime_map
        .get("reporting_and_signoff_contract")
        .and_then(|contract| contract.get("report_cadence"))
        .and_then(Value::as_array)
        .expect("reporting_and_signoff_contract.report_cadence must be an array")
        .iter()
        .map(|entry| {
            entry
                .get("cadence_id")
                .and_then(Value::as_str)
                .expect("report_cadence cadence_id must be a string")
                .to_string()
        })
        .collect::<BTreeSet<_>>();

    let invariant_ids = link_rows(&link_map)
        .iter()
        .map(|row| {
            row.get("invariant_id")
                .and_then(Value::as_str)
                .expect("invariant_id must be string")
                .to_string()
        })
        .collect::<BTreeSet<_>>();

    assert_assumption_class_matrix(contract, &required_classes, &invariant_ids, &cadence_ids);
    assert_incident_triage_flow(contract);
}

fn assert_cross_entity_contract_identity(contract: &Value) {
    assert_eq!(
        contract
            .get("contract_id")
            .and_then(Value::as_str)
            .expect("contract_id must be a string"),
        "lean.track3.cross_entity_liveness.v1"
    );
    assert_eq!(
        contract
            .get("source_bead")
            .and_then(Value::as_str)
            .expect("source_bead must be a string"),
        "asupersync-24rak"
    );
}

fn assert_cross_entity_invariant_links(contract: &Value, link_map: &Value) {
    let linked_invariants = contract
        .get("invariant_ids")
        .and_then(Value::as_array)
        .expect("invariant_ids must be an array")
        .iter()
        .map(|entry| {
            entry
                .as_str()
                .expect("invariant_ids entries must be strings")
        })
        .collect::<BTreeSet<_>>();
    assert_eq!(
        linked_invariants,
        BTreeSet::from([
            "inv.cancel.protocol",
            "inv.race.losers_drained",
            "inv.region_close.quiescence",
        ])
    );

    let known_invariants = link_rows(link_map)
        .iter()
        .map(|row| {
            row.get("invariant_id")
                .and_then(Value::as_str)
                .expect("invariant_id must be string")
        })
        .collect::<BTreeSet<_>>();
    for invariant_id in &linked_invariants {
        assert!(
            known_invariants.contains(invariant_id),
            "cross-entity contract references unknown invariant_id {invariant_id}"
        );
    }
}

fn assert_cross_entity_assumption_catalog(contract: &Value) -> BTreeSet<String> {
    let assumptions = contract
        .get("assumption_catalog")
        .and_then(Value::as_array)
        .expect("assumption_catalog must be an array");
    let mut ids = BTreeSet::new();
    for assumption in assumptions {
        let assumption_id = assumption
            .get("assumption_id")
            .and_then(Value::as_str)
            .expect("assumption_id must be a string");
        assert!(
            ids.insert(assumption_id.to_string()),
            "assumption_catalog must not repeat assumption_id {assumption_id}"
        );
        assert!(
            assumption
                .get("statement")
                .and_then(Value::as_str)
                .is_some_and(|value| !value.trim().is_empty()),
            "assumption_catalog.{assumption_id}.statement must be non-empty"
        );
    }
    assert_eq!(
        ids,
        BTreeSet::from([
            "assume.cancel.checkpoint_observability.v1".to_string(),
            "assume.cancel.streak_fairness_bound.v1".to_string(),
            "assume.race.loser_drain_waits.v1".to_string(),
            "assume.close.quiescence_guard.v1".to_string(),
        ]),
        "assumption_catalog must carry canonical cross-entity assumption IDs"
    );
    ids
}

#[allow(clippy::too_many_lines)]
fn assert_cross_entity_theorem_chain(
    contract: &Value,
    theorem_index: &BTreeMap<String, u64>,
    assumption_ids: &BTreeSet<String>,
) {
    let theorem_chain = contract
        .get("theorem_chain")
        .and_then(Value::as_array)
        .expect("theorem_chain must be an array");
    let mut seen_segments = BTreeSet::new();
    for segment in theorem_chain {
        let segment_id = segment
            .get("segment_id")
            .and_then(Value::as_str)
            .expect("segment_id must be a string");
        assert!(
            seen_segments.insert(segment_id),
            "theorem_chain must not repeat segment_id {segment_id}"
        );
        assert!(
            segment
                .get("guarantee")
                .and_then(Value::as_str)
                .is_some_and(|value| !value.trim().is_empty()),
            "theorem_chain.{segment_id}.guarantee must be non-empty"
        );
        let theorems = segment
            .get("theorems")
            .and_then(Value::as_array)
            .expect("segment theorems must be an array");
        assert!(
            !theorems.is_empty(),
            "theorem_chain.{segment_id} must list at least one theorem"
        );
        for theorem in theorems {
            let theorem = theorem
                .as_str()
                .expect("segment theorem entries must be strings");
            assert!(
                theorem_index.contains_key(theorem),
                "theorem_chain.{segment_id} references unknown theorem {theorem}"
            );
        }

        let theorem_sources = segment
            .get("theorem_sources")
            .and_then(Value::as_array)
            .expect("theorem_sources must be an array");
        assert!(
            !theorem_sources.is_empty(),
            "theorem_chain.{segment_id}.theorem_sources must be non-empty"
        );
        let mut source_lines = BTreeMap::new();
        for source in theorem_sources {
            let theorem = source
                .get("theorem")
                .and_then(Value::as_str)
                .expect("theorem_sources.theorem must be a string");
            let line = source
                .get("line")
                .and_then(Value::as_u64)
                .expect("theorem_sources.line must be numeric");
            assert!(
                source
                    .get("file")
                    .and_then(Value::as_str)
                    .is_some_and(|path| Path::new(path).exists()),
                "theorem_sources.file must exist for theorem {theorem}"
            );
            let expected = theorem_index
                .get(theorem)
                .unwrap_or_else(|| panic!("unknown theorem in theorem_sources: {theorem}"));
            assert_eq!(
                line, *expected,
                "theorem_sources line mismatch for {theorem}"
            );
            source_lines.insert(theorem.to_string(), line);
        }
        for theorem in theorems {
            let theorem = theorem
                .as_str()
                .expect("segment theorem entries must be strings");
            assert!(
                source_lines.contains_key(theorem),
                "theorem_chain.{segment_id}.theorem_sources missing theorem {theorem}"
            );
        }

        let segment_assumptions = segment
            .get("assumption_ids")
            .and_then(Value::as_array)
            .expect("segment assumption_ids must be an array");
        assert!(
            !segment_assumptions.is_empty(),
            "theorem_chain.{segment_id}.assumption_ids must be non-empty"
        );
        for assumption in segment_assumptions {
            let assumption = assumption
                .as_str()
                .expect("segment assumption_ids entries must be strings");
            assert!(
                assumption_ids.contains(assumption),
                "theorem_chain.{segment_id} references unknown assumption_id {assumption}"
            );
        }
    }
    assert_eq!(
        seen_segments,
        BTreeSet::from(["cancel_ladder", "race_loser_drain", "close_quiescence"]),
        "theorem_chain must include canonical cross-entity liveness segments"
    );
}

fn cross_entity_harness_field_map(runtime_map: &Value) -> BTreeMap<String, BTreeSet<String>> {
    runtime_map
        .get("conformance_harness_contract")
        .and_then(|contract| contract.get("harnesses"))
        .and_then(Value::as_array)
        .expect("runtime map harnesses must be an array")
        .iter()
        .map(|harness| {
            let harness_id = harness
                .get("harness_id")
                .and_then(Value::as_str)
                .expect("runtime harness_id must be a string")
                .to_string();
            let fields = BTreeSet::from([
                "normalized_trace_artifact".to_string(),
                "mismatch_payload_artifact".to_string(),
                "repro_manifest_artifact".to_string(),
            ]);
            (harness_id, fields)
        })
        .collect::<BTreeMap<_, _>>()
}

fn assert_cross_entity_harness_links(
    contract: &Value,
    harness_field_map: &BTreeMap<String, BTreeSet<String>>,
) -> BTreeSet<String> {
    let harness_links = contract
        .get("conformance_harness_links")
        .and_then(Value::as_array)
        .expect("conformance_harness_links must be an array");
    let mut contract_harness_ids = BTreeSet::new();
    for link in harness_links {
        let harness_id = link
            .get("harness_id")
            .and_then(Value::as_str)
            .expect("harness_id must be a string");
        contract_harness_ids.insert(harness_id.to_string());
        let available_fields = harness_field_map
            .get(harness_id)
            .unwrap_or_else(|| panic!("unknown harness_id in cross-entity contract: {harness_id}"));
        let required_artifacts = link
            .get("required_artifacts")
            .and_then(Value::as_array)
            .expect("required_artifacts must be an array");
        assert!(
            !required_artifacts.is_empty(),
            "cross-entity harness link {harness_id} must require at least one artifact"
        );
        for field in required_artifacts {
            let field = field
                .as_str()
                .expect("required_artifacts entries must be strings");
            assert!(
                available_fields.contains(field),
                "cross-entity harness link {harness_id} references unknown artifact field {field}"
            );
        }
    }
    contract_harness_ids
}

fn assert_cross_entity_end_to_end_guarantees(
    contract: &Value,
    theorem_index: &BTreeMap<String, u64>,
    contract_harness_ids: &BTreeSet<String>,
    assumption_ids: &BTreeSet<String>,
) {
    let guarantees = contract
        .get("end_to_end_guarantees")
        .and_then(Value::as_array)
        .expect("end_to_end_guarantees must be an array");
    let mut seen_guarantees = BTreeSet::new();
    for guarantee in guarantees {
        let guarantee_id = guarantee
            .get("guarantee_id")
            .and_then(Value::as_str)
            .expect("guarantee_id must be a string");
        assert!(
            seen_guarantees.insert(guarantee_id),
            "end_to_end_guarantees must not repeat guarantee_id {guarantee_id}"
        );
        assert!(
            guarantee
                .get("statement")
                .and_then(Value::as_str)
                .is_some_and(|value| !value.trim().is_empty()),
            "end_to_end_guarantees.{guarantee_id}.statement must be non-empty"
        );
        let theorem_deps = guarantee
            .get("depends_on_theorems")
            .and_then(Value::as_array)
            .expect("depends_on_theorems must be an array");
        assert!(
            !theorem_deps.is_empty(),
            "end_to_end_guarantees.{guarantee_id} must define depends_on_theorems"
        );
        for theorem in theorem_deps {
            let theorem = theorem
                .as_str()
                .expect("depends_on_theorems entries must be strings");
            assert!(
                theorem_index.contains_key(theorem),
                "end_to_end_guarantees.{guarantee_id} references unknown theorem {theorem}"
            );
        }
        let guarantee_assumptions = guarantee
            .get("assumption_ids")
            .and_then(Value::as_array)
            .expect("assumption_ids must be an array");
        assert!(
            !guarantee_assumptions.is_empty(),
            "end_to_end_guarantees.{guarantee_id} must define assumption_ids"
        );
        for assumption in guarantee_assumptions {
            let assumption = assumption
                .as_str()
                .expect("assumption_ids entries must be strings");
            assert!(
                assumption_ids.contains(assumption),
                "end_to_end_guarantees.{guarantee_id} references unknown assumption_id {assumption}"
            );
        }
        let harness_ids = guarantee
            .get("harness_ids")
            .and_then(Value::as_array)
            .expect("harness_ids must be an array");
        assert!(
            !harness_ids.is_empty(),
            "end_to_end_guarantees.{guarantee_id} must define harness_ids"
        );
        for harness_id in harness_ids {
            let harness_id = harness_id
                .as_str()
                .expect("harness_ids entries must be strings");
            assert!(
                contract_harness_ids.contains(harness_id),
                "end_to_end_guarantees.{guarantee_id} references unknown harness_id {harness_id}"
            );
        }
        let consumers = guarantee
            .get("consumed_by")
            .and_then(Value::as_array)
            .expect("consumed_by must be an array");
        assert!(
            !consumers.is_empty(),
            "end_to_end_guarantees.{guarantee_id} must define consumed_by"
        );
        for consumer in consumers {
            let consumer = consumer
                .as_str()
                .expect("consumed_by entries must be strings");
            assert!(
                Path::new(consumer).exists(),
                "end_to_end_guarantees.{guarantee_id} consumer path missing: {consumer}"
            );
        }
    }
}

#[test]
fn cross_entity_liveness_contract_composes_theorem_chain_into_harness_consumers() {
    let link_map = parse_json(LINK_MAP_JSON, "link map");
    let theorem_inventory = parse_json(THEOREM_JSON, "theorem inventory");
    let runtime_map = parse_json(RUNTIME_MAP_JSON, "runtime_state_refinement_map");
    let contract = link_map
        .get("cross_entity_liveness_composition")
        .expect("cross_entity_liveness_composition must exist");

    assert_cross_entity_contract_identity(contract);
    assert_cross_entity_invariant_links(contract, &link_map);
    let assumption_ids = assert_cross_entity_assumption_catalog(contract);

    let theorem_index = theorem_lines(&theorem_inventory);
    assert_cross_entity_theorem_chain(contract, &theorem_index, &assumption_ids);

    let harness_field_map = cross_entity_harness_field_map(&runtime_map);
    let contract_harness_ids = assert_cross_entity_harness_links(contract, &harness_field_map);
    assert_cross_entity_end_to_end_guarantees(
        contract,
        &theorem_index,
        &contract_harness_ids,
        &assumption_ids,
    );
}
