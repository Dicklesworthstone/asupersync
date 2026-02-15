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
const BEADS_JSONL: &str = include_str!("../.beads/issues.jsonl");

#[derive(Debug)]
struct InvariantExpectations {
    name: String,
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

#[test]
fn liveness_invariants_have_termination_quiescence_and_gap_contracts() {
    let link_map = parse_json(LINK_MAP_JSON, "link map");
    let rows = link_rows(&link_map);
    assert_cancel_liveness_row(invariant_row(rows, "inv.cancel.protocol"));
    assert_quiescence_liveness_row(invariant_row(rows, "inv.region_close.quiescence"));
    assert_loser_drain_liveness_row(invariant_row(rows, "inv.race.losers_drained"));
}
