//! Gap classification/risk/sequencing consistency checks (bd-1vhw5).

use serde_json::Value;
use std::collections::BTreeSet;

const PLAN_JSON: &str = include_str!("../formal/lean/coverage/gap_risk_sequencing_plan.json");
const BEADS_JSONL: &str = include_str!("../.beads/issues.jsonl");

fn parse_plan() -> Value {
    serde_json::from_str(PLAN_JSON).expect("gap plan must parse")
}

fn bead_identifiers() -> BTreeSet<String> {
    BEADS_JSONL
        .lines()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .flat_map(|entry| {
            let mut ids = Vec::new();
            if let Some(id) = entry.get("id").and_then(Value::as_str) {
                ids.push(id.to_string());
            }
            if let Some(external_ref) = entry.get("external_ref").and_then(Value::as_str) {
                ids.push(external_ref.to_string());
            }
            ids
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
    let bead_ids = bead_identifiers();

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

#[test]
#[allow(clippy::too_many_lines)]
fn coverage_gate_policy_thresholds_and_escalation_contract_are_well_formed() {
    let plan = parse_plan();
    let policy = plan
        .get("coverage_gate_policy")
        .and_then(Value::as_object)
        .expect("coverage_gate_policy must be an object");

    assert_eq!(
        policy
            .get("policy_version")
            .and_then(Value::as_str)
            .expect("policy_version must be a string"),
        "1.0.0"
    );
    assert_eq!(
        policy
            .get("policy_id")
            .and_then(Value::as_str)
            .expect("policy_id must be a string"),
        "lean.coverage.gates.thresholds.v1"
    );

    let governance_reference = policy
        .get("governance_reference_time_utc")
        .and_then(Value::as_str)
        .expect("governance_reference_time_utc must be string");
    assert!(
        governance_reference.ends_with('Z'),
        "governance_reference_time_utc must be UTC"
    );

    let expected_categories = [
        "theorem",
        "constructor",
        "invariant",
        "conformance",
        "frontier",
    ]
    .into_iter()
    .collect::<BTreeSet<_>>();
    let bead_ids = bead_identifiers();

    let category_thresholds = policy
        .get("category_thresholds")
        .and_then(Value::as_array)
        .expect("category_thresholds must be an array");
    assert!(
        !category_thresholds.is_empty(),
        "category_thresholds must not be empty"
    );

    let mut threshold_categories = BTreeSet::new();
    for threshold in category_thresholds {
        let category = threshold
            .get("category")
            .and_then(Value::as_str)
            .expect("threshold.category must be string");
        threshold_categories.insert(category);
        assert!(
            expected_categories.contains(category),
            "unexpected threshold category: {category}"
        );

        let metric = threshold
            .get("metric")
            .and_then(Value::as_str)
            .expect("threshold.metric must be string");
        assert!(
            !metric.is_empty(),
            "metric must be non-empty for {category}"
        );

        let comparator = threshold
            .get("comparator")
            .and_then(Value::as_str)
            .expect("threshold.comparator must be string");
        assert!(
            matches!(comparator, ">=" | "<="),
            "unsupported comparator {comparator} for {category}"
        );

        let threshold_value = threshold
            .get("threshold")
            .and_then(Value::as_f64)
            .expect("threshold.threshold must be numeric");
        assert!(
            threshold_value.is_finite() && threshold_value >= 0.0,
            "threshold must be finite and non-negative for {category}"
        );

        let owner_role = threshold
            .get("owner_role")
            .and_then(Value::as_str)
            .expect("threshold.owner_role must be string");
        assert!(
            !owner_role.is_empty(),
            "owner_role must be non-empty for {category}"
        );

        let owner_bead = threshold
            .get("owner_bead")
            .and_then(Value::as_str)
            .expect("threshold.owner_bead must be string");
        assert!(
            bead_ids.contains(owner_bead),
            "threshold.owner_bead must reference an existing bead: {owner_bead}"
        );
    }
    assert_eq!(
        threshold_categories, expected_categories,
        "category_thresholds must cover theorem/constructor/invariant/conformance/frontier"
    );

    let escalation_policy = policy
        .get("escalation_policy")
        .and_then(Value::as_object)
        .expect("escalation_policy must be an object");

    let assignment_rules = escalation_policy
        .get("owner_assignment_rules")
        .and_then(Value::as_array)
        .expect("owner_assignment_rules must be an array");
    let mut assignment_categories = BTreeSet::new();
    for rule in assignment_rules {
        let category = rule
            .get("category")
            .and_then(Value::as_str)
            .expect("owner_assignment_rules.category must be string");
        assignment_categories.insert(category);
        assert!(
            expected_categories.contains(category),
            "unexpected assignment category: {category}"
        );

        let primary_owner_bead = rule
            .get("primary_owner_bead")
            .and_then(Value::as_str)
            .expect("primary_owner_bead must be string");
        assert!(
            bead_ids.contains(primary_owner_bead),
            "unknown primary_owner_bead: {primary_owner_bead}"
        );

        let escalation_bead = rule
            .get("escalation_bead")
            .and_then(Value::as_str)
            .expect("escalation_bead must be string");
        assert!(
            bead_ids.contains(escalation_bead),
            "unknown escalation_bead: {escalation_bead}"
        );
    }
    assert_eq!(
        assignment_categories, expected_categories,
        "owner_assignment_rules must cover every threshold category"
    );

    let sla_targets = escalation_policy
        .get("sla_targets")
        .and_then(Value::as_array)
        .expect("sla_targets must be an array");
    let mut warning_response_minutes = None;
    let mut high_response_minutes = None;
    let mut critical_response_minutes = None;
    let mut warning_resolution_hours = None;
    let mut high_resolution_hours = None;
    let mut critical_resolution_hours = None;
    for sla in sla_targets {
        let severity = sla
            .get("severity")
            .and_then(Value::as_str)
            .expect("sla severity must be string");
        let response_minutes = sla
            .get("ttfr_minutes")
            .and_then(Value::as_u64)
            .expect("ttfr_minutes must be numeric");
        let resolution_hours = sla
            .get("ttr_hours")
            .and_then(Value::as_u64)
            .expect("ttr_hours must be numeric");
        let escalation_bead = sla
            .get("escalation_bead")
            .and_then(Value::as_str)
            .expect("sla escalation_bead must be string");
        assert!(
            bead_ids.contains(escalation_bead),
            "sla escalation_bead must reference known bead: {escalation_bead}"
        );

        match severity {
            "warning" => {
                warning_response_minutes = Some(response_minutes);
                warning_resolution_hours = Some(resolution_hours);
            }
            "high" => {
                high_response_minutes = Some(response_minutes);
                high_resolution_hours = Some(resolution_hours);
            }
            "critical" => {
                critical_response_minutes = Some(response_minutes);
                critical_resolution_hours = Some(resolution_hours);
            }
            other => panic!("unexpected SLA severity: {other}"),
        }
    }
    assert!(
        warning_response_minutes.is_some()
            && high_response_minutes.is_some()
            && critical_response_minutes.is_some(),
        "SLA targets must include warning/high/critical severities"
    );
    assert!(
        warning_resolution_hours.is_some()
            && high_resolution_hours.is_some()
            && critical_resolution_hours.is_some(),
        "SLA targets must include warning/high/critical TTR values"
    );
    assert!(
        warning_response_minutes.expect("warning TTFR") > high_response_minutes.expect("high TTFR")
            && high_response_minutes.expect("high TTFR")
                > critical_response_minutes.expect("critical TTFR"),
        "SLA TTFR must tighten as severity increases"
    );
    assert!(
        warning_resolution_hours.expect("warning TTR") > high_resolution_hours.expect("high TTR")
            && high_resolution_hours.expect("high TTR")
                > critical_resolution_hours.expect("critical TTR"),
        "SLA TTR must tighten as severity increases"
    );

    let allowed_regressions = escalation_policy
        .get("allowed_temporary_regressions")
        .and_then(Value::as_array)
        .expect("allowed_temporary_regressions must be an array");
    let mut allowed_categories = BTreeSet::new();
    for row in allowed_regressions {
        let category = row
            .get("category")
            .and_then(Value::as_str)
            .expect("allowed_temporary_regressions.category must be string");
        allowed_categories.insert(category);
        assert!(
            expected_categories.contains(category),
            "unexpected allowed_temporary_regressions category: {category}"
        );

        let max_regression_points = row
            .get("max_regression_points")
            .and_then(Value::as_f64)
            .expect("max_regression_points must be numeric");
        assert!(
            max_regression_points.is_finite() && max_regression_points >= 0.0,
            "max_regression_points must be finite and non-negative for {category}"
        );

        let max_expiry_days = row
            .get("max_expiry_days")
            .and_then(Value::as_u64)
            .expect("max_expiry_days must be numeric");
        assert!(
            (1..=30).contains(&max_expiry_days),
            "max_expiry_days out of range for {category}"
        );

        let approval_bead = row
            .get("approval_bead")
            .and_then(Value::as_str)
            .expect("approval_bead must be string");
        assert!(
            bead_ids.contains(approval_bead),
            "unknown approval_bead: {approval_bead}"
        );
    }
    assert_eq!(
        allowed_categories, expected_categories,
        "allowed_temporary_regressions must cover every threshold category"
    );

    let lifecycle = policy
        .get("exception_lifecycle")
        .and_then(Value::as_object)
        .expect("exception_lifecycle must be an object");
    assert_eq!(
        lifecycle
            .get("policy_id")
            .and_then(Value::as_str)
            .expect("exception_lifecycle.policy_id must be string"),
        "lean.coverage.exception_lifecycle.v1"
    );

    let required_fields = lifecycle
        .get("required_fields")
        .and_then(Value::as_array)
        .expect("exception_lifecycle.required_fields must be an array")
        .iter()
        .map(|field| {
            field
                .as_str()
                .expect("required field values must be strings")
        })
        .collect::<BTreeSet<_>>();
    for required in [
        "waiver_id",
        "category",
        "owner",
        "reason",
        "risk_class",
        "status",
        "opened_at_utc",
        "expires_at_utc",
        "approval_bead",
        "closure_dependency_path",
    ] {
        assert!(
            required_fields.contains(required),
            "missing required waiver field: {required}"
        );
    }

    let statuses = lifecycle
        .get("statuses")
        .and_then(Value::as_array)
        .expect("exception_lifecycle.statuses must be an array")
        .iter()
        .map(|status| status.as_str().expect("statuses must be strings"))
        .collect::<BTreeSet<_>>();
    for status in ["draft", "active", "closed", "expired"] {
        assert!(
            statuses.contains(status),
            "exception_lifecycle.statuses missing {status}"
        );
    }

    let lifecycle_checks = lifecycle
        .get("governance_checks")
        .and_then(Value::as_array)
        .expect("exception_lifecycle.governance_checks must be an array")
        .iter()
        .map(|check| {
            check
                .get("check_id")
                .and_then(Value::as_str)
                .expect("exception_lifecycle check_id must be string")
        })
        .collect::<BTreeSet<_>>();
    for check in [
        "waiver.expiry.enforced",
        "waiver.closed.requires_closure_bead",
    ] {
        assert!(
            lifecycle_checks.contains(check),
            "exception_lifecycle missing check {check}"
        );
    }

    let exceptions = policy
        .get("exceptions")
        .and_then(Value::as_array)
        .expect("exceptions must be an array");
    assert!(!exceptions.is_empty(), "exceptions must not be empty");
    let mut waiver_ids = BTreeSet::new();
    for waiver in exceptions {
        let waiver_id = waiver
            .get("waiver_id")
            .and_then(Value::as_str)
            .expect("waiver_id must be string");
        assert!(
            waiver_ids.insert(waiver_id.to_string()),
            "duplicate waiver_id: {waiver_id}"
        );

        for field in &required_fields {
            assert!(
                waiver.get(field).is_some(),
                "waiver {waiver_id} missing required field {field}"
            );
        }

        let category = waiver
            .get("category")
            .and_then(Value::as_str)
            .expect("waiver category must be string");
        assert!(
            expected_categories.contains(category),
            "waiver {waiver_id} has unknown category {category}"
        );

        let status = waiver
            .get("status")
            .and_then(Value::as_str)
            .expect("waiver status must be string");
        assert!(
            statuses.contains(status),
            "waiver {waiver_id} has unknown status {status}"
        );

        let opened_at = waiver
            .get("opened_at_utc")
            .and_then(Value::as_str)
            .expect("opened_at_utc must be string");
        let expires_at = waiver
            .get("expires_at_utc")
            .and_then(Value::as_str)
            .expect("expires_at_utc must be string");
        assert!(
            opened_at.ends_with('Z') && expires_at.ends_with('Z'),
            "waiver timestamps must be UTC strings"
        );

        let approval_bead = waiver
            .get("approval_bead")
            .and_then(Value::as_str)
            .expect("approval_bead must be string");
        assert!(
            bead_ids.contains(approval_bead),
            "waiver {waiver_id} references unknown approval_bead {approval_bead}"
        );

        let closure_path = waiver
            .get("closure_dependency_path")
            .and_then(Value::as_str)
            .expect("closure_dependency_path must be string");
        assert!(
            !closure_path.is_empty(),
            "waiver {waiver_id} closure_dependency_path must be non-empty"
        );

        if status == "active" {
            assert!(
                expires_at > governance_reference,
                "active waiver {waiver_id} is expired at governance reference time"
            );
        }
        if status == "closed" {
            let closure_bead = waiver
                .get("closure_bead")
                .and_then(Value::as_str)
                .expect("closed waiver must include closure_bead");
            assert!(
                bead_ids.contains(closure_bead),
                "closed waiver {waiver_id} closure_bead must reference known bead"
            );
            let closed_at = waiver
                .get("closed_at_utc")
                .and_then(Value::as_str)
                .expect("closed waiver must include closed_at_utc");
            assert!(
                closed_at.ends_with('Z'),
                "closed waiver {waiver_id} closed_at_utc must be UTC"
            );
        }
    }

    let governance_checks = policy
        .get("governance_checks")
        .and_then(Value::as_array)
        .expect("governance_checks must be an array")
        .iter()
        .map(|check| {
            check
                .get("check_id")
                .and_then(Value::as_str)
                .expect("governance check_id must be string")
        })
        .collect::<BTreeSet<_>>();
    for check in [
        "coverage.threshold.categories.complete",
        "coverage.escalation.owner_assignment.complete",
        "coverage.sla.targets.ordered",
        "coverage.waiver.lifecycle.enforced",
    ] {
        assert!(
            governance_checks.contains(check),
            "coverage_gate_policy missing governance check {check}"
        );
    }
}
