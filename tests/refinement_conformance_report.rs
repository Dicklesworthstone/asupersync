//! Deterministic refinement conformance report contract checks (bd-1psg4).

use serde_json::Value;
use std::collections::BTreeSet;

const REPORT_JSON: &str =
    include_str!("../formal/lean/coverage/refinement_conformance_report_v1.json");
const MAP_JSON: &str = include_str!("../formal/lean/coverage/runtime_state_refinement_map.json");

fn object<'a>(value: &'a Value, ctx: &str) -> &'a serde_json::Map<String, Value> {
    value.as_object().unwrap_or_else(|| panic!("{ctx} must be object"))
}

fn as_array<'a>(value: &'a Value, ctx: &str) -> &'a [Value] {
    value.as_array().unwrap_or_else(|| panic!("{ctx} must be array"))
}

fn as_str<'a>(value: &'a Value, ctx: &str) -> &'a str {
    value.as_str().unwrap_or_else(|| panic!("{ctx} must be string"))
}

fn str_set(values: &[Value], ctx: &str) -> BTreeSet<String> {
    values
        .iter()
        .map(|v| as_str(v, ctx).to_string())
        .collect::<BTreeSet<_>>()
}

#[test]
fn refinement_report_has_required_shape_and_signal_fields() {
    let report: Value = serde_json::from_str(REPORT_JSON).expect("report JSON must parse");
    let report_obj = object(&report, "report");

    assert_eq!(
        as_str(
            report_obj
                .get("schema_version")
                .expect("schema_version required"),
            "schema_version",
        ),
        "1.0.0"
    );
    assert_eq!(
        as_str(
            report_obj.get("report_id").expect("report_id required"),
            "report_id",
        ),
        "lean.refinement_conformance_report.v1"
    );

    for required in [
        "coverage_percent",
        "mismatch_trend",
        "unresolved_blockers",
        "confidence_statement",
        "generated_at",
        "required_artifacts",
        "required_tests",
        "next_actions",
        "signoff_checklist",
        "cadence_and_ownership",
        "track6_input",
    ] {
        assert!(report_obj.contains_key(required), "missing report field {required}");
    }

    let coverage = object(
        report_obj
            .get("coverage_percent")
            .expect("coverage_percent required"),
        "coverage_percent",
    );
    for key in ["mapped_operations", "conformance_harnesses", "invariant_test_links"] {
        let pct = coverage
            .get(key)
            .and_then(Value::as_f64)
            .unwrap_or_else(|| panic!("coverage_percent.{key} must be number"));
        assert!((0.0..=100.0).contains(&pct), "coverage_percent.{key} out of range");
    }

    let mismatch = object(
        report_obj
            .get("mismatch_trend")
            .expect("mismatch_trend required"),
        "mismatch_trend",
    );
    assert!(
        matches!(
            as_str(mismatch.get("trend").expect("mismatch trend required"), "mismatch_trend.trend"),
            "improving" | "flat" | "regressing"
        ),
        "mismatch_trend.trend must be known enum"
    );

    let confidence = object(
        report_obj
            .get("confidence_statement")
            .expect("confidence_statement required"),
        "confidence_statement",
    );
    assert!(
        matches!(
            as_str(
                confidence.get("level").expect("confidence level required"),
                "confidence_statement.level"
            ),
            "low" | "medium" | "high"
        ),
        "confidence_statement.level must be known enum"
    );
}

#[test]
fn refinement_report_is_consistent_with_runtime_state_contract() {
    let report: Value = serde_json::from_str(REPORT_JSON).expect("report JSON must parse");
    let map: Value = serde_json::from_str(MAP_JSON).expect("map JSON must parse");

    let report_obj = object(&report, "report");
    let map_contract = object(
        map.get("reporting_and_signoff_contract")
            .expect("reporting_and_signoff_contract required"),
        "reporting_and_signoff_contract",
    );

    let required_report_fields = str_set(
        as_array(
            map_contract
                .get("required_report_fields")
                .expect("required_report_fields required"),
            "required_report_fields",
        ),
        "required_report_fields[]",
    );
    for field in required_report_fields {
        assert!(
            report_obj.contains_key(&field),
            "report missing contract-required field {field}"
        );
    }

    let report_artifacts = str_set(
        as_array(
            report_obj
                .get("required_artifacts")
                .expect("required_artifacts required"),
            "required_artifacts",
        ),
        "required_artifacts[]",
    );
    let contract_artifacts = str_set(
        as_array(
            map_contract
                .get("required_artifact_refs")
                .expect("required_artifact_refs required"),
            "required_artifact_refs",
        ),
        "required_artifact_refs[]",
    );
    assert_eq!(
        report_artifacts, contract_artifacts,
        "required_artifacts must match map contract"
    );

    let report_tests = str_set(
        as_array(
            report_obj
                .get("required_tests")
                .expect("required_tests required"),
            "required_tests",
        ),
        "required_tests[]",
    );
    let contract_tests = str_set(
        as_array(
            map_contract
                .get("required_test_refs")
                .expect("required_test_refs required"),
            "required_test_refs",
        ),
        "required_test_refs[]",
    );
    assert_eq!(report_tests, contract_tests, "required_tests must match map contract");

    let report_check_ids = as_array(
        report_obj
            .get("signoff_checklist")
            .expect("signoff_checklist required"),
        "signoff_checklist",
    )
    .iter()
    .map(|item| {
        as_str(
            item.get("check_id").expect("signoff checklist check_id required"),
            "signoff_checklist[].check_id",
        )
    })
    .collect::<BTreeSet<_>>();

    let contract_check_ids = as_array(
        map_contract
            .get("signoff_checklist")
            .expect("contract signoff_checklist required"),
        "contract.signoff_checklist",
    )
    .iter()
    .map(|item| {
        as_str(
            item.get("check_id")
                .expect("contract signoff checklist check_id required"),
            "contract.signoff_checklist[].check_id",
        )
    })
    .collect::<BTreeSet<_>>();

    assert_eq!(
        report_check_ids, contract_check_ids,
        "signoff checklist IDs must match runtime_state_refinement_map contract"
    );

    let cadence_and_ownership = object(
        report_obj
            .get("cadence_and_ownership")
            .expect("cadence_and_ownership required"),
        "cadence_and_ownership",
    );
    let governance_links = str_set(
        as_array(
            cadence_and_ownership
                .get("governance_links")
                .expect("governance_links required"),
            "governance_links",
        ),
        "governance_links[]",
    );
    let contract_governance_links = str_set(
        as_array(
            map_contract
                .get("governance_links")
                .expect("contract governance_links required"),
            "contract.governance_links",
        ),
        "contract.governance_links[]",
    );
    assert_eq!(
        governance_links, contract_governance_links,
        "governance links must match contract"
    );

    let track6_report = object(
        report_obj
            .get("track6_input")
            .expect("track6_input required"),
        "track6_input",
    );
    let track6_contract = object(
        map_contract
            .get("track6_input_contract")
            .expect("track6_input_contract required"),
        "track6_input_contract",
    );
    let export_report = str_set(
        as_array(
            track6_report
                .get("export_fields")
                .expect("track6_input.export_fields required"),
            "track6_input.export_fields",
        ),
        "track6_input.export_fields[]",
    );
    let export_contract = str_set(
        as_array(
            track6_contract
                .get("export_fields")
                .expect("track6_input_contract.export_fields required"),
            "track6_input_contract.export_fields",
        ),
        "track6_input_contract.export_fields[]",
    );
    assert_eq!(
        export_report, export_contract,
        "track6 export_fields must match contract"
    );
}
