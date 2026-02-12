//! Gap classification/risk/sequencing consistency checks (bd-1vhw5).

use serde_json::Value;
use std::collections::BTreeSet;

const PLAN_JSON: &str = include_str!("../formal/lean/coverage/gap_risk_sequencing_plan.json");
const BEADS_JSONL: &str = include_str!("../.beads/issues.jsonl");

fn parse_plan() -> Value {
    serde_json::from_str(PLAN_JSON).expect("gap plan must parse")
}

fn bead_ids() -> BTreeSet<String> {
    BEADS_JSONL
        .lines()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .filter_map(|entry| {
            entry
                .get("id")
                .and_then(Value::as_str)
                .map(ToString::to_string)
        })
        .collect::<BTreeSet<_>>()
}

fn plan_gaps(plan: &Value) -> &[Value] {
    plan.get("gaps")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .expect("gaps must be an array")
}

fn gap_ids(gaps: &[Value]) -> BTreeSet<String> {
    gaps.iter()
        .map(|gap| {
            gap.get("id")
                .and_then(Value::as_str)
                .expect("gap id must be a string")
                .to_string()
        })
        .collect::<BTreeSet<_>>()
}

#[test]
fn gap_rows_have_valid_modes_scores_and_bead_links() {
    let plan = parse_plan();
    assert_eq!(
        plan.get("schema_version")
            .and_then(Value::as_str)
            .expect("schema_version must be a string"),
        "1.0.0"
    );

    let allowed_failure_modes = plan
        .get("failure_mode_catalog")
        .and_then(Value::as_array)
        .expect("failure_mode_catalog must be an array")
        .iter()
        .map(|entry| {
            entry
                .get("code")
                .and_then(Value::as_str)
                .expect("failure_mode code must be a string")
        })
        .collect::<BTreeSet<_>>();

    let gaps = plan_gaps(&plan);
    assert!(!gaps.is_empty(), "gap plan must include at least one gap");

    let mut gap_ids = BTreeSet::new();
    let bead_ids = bead_ids();

    for gap in gaps {
        let id = gap
            .get("id")
            .and_then(Value::as_str)
            .expect("gap id must be a string");
        assert!(gap_ids.insert(id), "duplicate gap id: {id}");

        let failure_mode = gap
            .get("failure_mode")
            .and_then(Value::as_str)
            .expect("failure_mode must be a string");
        assert!(
            allowed_failure_modes.contains(failure_mode),
            "unknown failure_mode '{failure_mode}' for gap {id}"
        );

        let product_risk = gap
            .get("product_risk")
            .and_then(Value::as_u64)
            .expect("product_risk must be numeric");
        let unblock_potential = gap
            .get("unblock_potential")
            .and_then(Value::as_u64)
            .expect("unblock_potential must be numeric");
        let implementation_effort = gap
            .get("implementation_effort")
            .and_then(Value::as_u64)
            .expect("implementation_effort must be numeric");
        let priority_score = gap
            .get("priority_score")
            .and_then(Value::as_i64)
            .expect("priority_score must be numeric");

        assert!(
            (1..=5).contains(&product_risk),
            "product_risk out of range for {id}"
        );
        assert!(
            (1..=5).contains(&unblock_potential),
            "unblock_potential out of range for {id}"
        );
        assert!(
            (1..=5).contains(&implementation_effort),
            "implementation_effort out of range for {id}"
        );

        let expected_priority = (2 * i128::from(product_risk)) + i128::from(unblock_potential)
            - i128::from(implementation_effort);
        assert_eq!(
            i128::from(priority_score),
            expected_priority,
            "priority_score formula mismatch for {id}"
        );

        let linked_beads = gap
            .get("linked_beads")
            .and_then(Value::as_array)
            .expect("linked_beads must be an array");
        assert!(
            !linked_beads.is_empty(),
            "linked_beads must not be empty for {id}"
        );
        for bead in linked_beads {
            let bead_id = bead
                .as_str()
                .expect("linked bead ids must be string values");
            assert!(
                bead_ids.contains(bead_id),
                "gap {id} references unknown bead {bead_id}"
            );
        }
    }
}

#[test]
fn blockers_and_priority_order_are_consistent() {
    let plan = parse_plan();
    let gaps = plan_gaps(&plan);
    let gap_ids = gap_ids(gaps);

    let high_risk_gap_ids = gaps
        .iter()
        .filter_map(|gap| {
            let id = gap.get("id").and_then(Value::as_str)?;
            let product_risk = gap.get("product_risk").and_then(Value::as_u64)?;
            let priority_score = gap.get("priority_score").and_then(Value::as_i64)?;
            if product_risk >= 5 || priority_score >= 11 {
                Some(id.to_string())
            } else {
                None
            }
        })
        .collect::<BTreeSet<_>>();

    let first_class = plan
        .get("first_class_blockers")
        .and_then(Value::as_array)
        .expect("first_class_blockers must be an array")
        .iter()
        .map(|entry| {
            entry
                .as_str()
                .expect("first_class blocker ids must be strings")
                .to_string()
        })
        .collect::<BTreeSet<_>>();
    for blocker in &first_class {
        assert!(
            gap_ids.contains(blocker),
            "first_class blocker {blocker} is missing from gaps"
        );
    }
    assert!(
        first_class.is_subset(&high_risk_gap_ids),
        "first_class blockers must be high-risk gaps"
    );

    let priority_order = plan
        .get("priority_order")
        .and_then(Value::as_array)
        .expect("priority_order must be an array")
        .iter()
        .map(|entry| {
            entry
                .as_str()
                .expect("priority_order entries must be strings")
        })
        .collect::<Vec<_>>();
    assert_eq!(
        priority_order.len(),
        gap_ids.len(),
        "priority_order must include every gap exactly once"
    );
    assert_eq!(
        priority_order.iter().collect::<BTreeSet<_>>().len(),
        gap_ids.len(),
        "priority_order must not contain duplicates"
    );
    for gap_id in &priority_order {
        assert!(
            gap_ids.contains(*gap_id),
            "priority_order references unknown gap {gap_id}"
        );
    }
}

#[test]
fn sequencing_graph_and_critical_path_are_consistent() {
    let plan = parse_plan();
    let gaps = plan_gaps(&plan);
    let gap_ids = gap_ids(gaps);
    let sequencing = plan
        .get("sequencing")
        .expect("sequencing section must exist");

    let track_order = sequencing
        .get("recommended_track_order")
        .and_then(Value::as_array)
        .expect("recommended_track_order must be an array")
        .iter()
        .map(|entry| entry.as_str().expect("track names must be strings"))
        .collect::<Vec<_>>();
    assert_eq!(
        track_order,
        vec!["track-2", "track-3", "track-4", "track-5", "track-6"],
        "recommended_track_order must follow Track-2 through Track-6 progression"
    );

    let edges = sequencing
        .get("dependency_edges")
        .and_then(Value::as_array)
        .expect("dependency_edges must be an array");
    let mut edge_lookup = BTreeSet::new();
    for edge in edges {
        let from_gap = edge
            .get("from_gap")
            .and_then(Value::as_str)
            .expect("from_gap must be a string");
        let to_gap = edge
            .get("to_gap")
            .and_then(Value::as_str)
            .expect("to_gap must be a string");
        assert!(gap_ids.contains(from_gap), "unknown from_gap {from_gap}");
        assert!(gap_ids.contains(to_gap), "unknown to_gap {to_gap}");
        edge_lookup.insert((from_gap.to_string(), to_gap.to_string()));
    }

    let critical_path = sequencing
        .get("critical_path")
        .and_then(Value::as_array)
        .expect("critical_path must be an array")
        .iter()
        .map(|entry| {
            entry
                .as_str()
                .expect("critical path values must be strings")
        })
        .collect::<Vec<_>>();
    assert!(critical_path.len() >= 2, "critical_path must include edges");
    for gap_id in &critical_path {
        assert!(
            gap_ids.contains(*gap_id),
            "critical_path references unknown gap {gap_id}"
        );
    }
    for pair in critical_path.windows(2) {
        let from = pair[0].to_string();
        let to = pair[1].to_string();
        assert!(
            edge_lookup.contains(&(from.clone(), to.clone())),
            "critical path edge missing from dependency_edges: {from} -> {to}"
        );
    }
}
