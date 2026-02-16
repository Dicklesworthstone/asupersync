//! Proof-guided performance opportunity map contract checks (bd-1lda7).

use serde_json::Value;
use std::collections::BTreeSet;

const MAP_JSON: &str =
    include_str!("../formal/lean/coverage/proof_guided_performance_opportunity_map.json");
const BEADS_JSONL: &str = include_str!("../.beads/issues.jsonl");

fn bead_ids() -> BTreeSet<String> {
    BEADS_JSONL
        .lines()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .fold(BTreeSet::new(), |mut ids, entry| {
            if let Some(id) = entry.get("id").and_then(Value::as_str) {
                ids.insert(id.to_string());
            }
            if let Some(external_ref) = entry.get("external_ref").and_then(Value::as_str) {
                ids.insert(external_ref.to_string());
            }
            ids
        })
}

fn as_array<'a>(value: &'a Value, ctx: &str) -> &'a [Value] {
    value
        .as_array()
        .unwrap_or_else(|| panic!("{ctx} must be an array"))
}

fn as_object<'a>(value: &'a Value, ctx: &str) -> &'a serde_json::Map<String, Value> {
    value
        .as_object()
        .unwrap_or_else(|| panic!("{ctx} must be an object"))
}

fn as_str<'a>(value: &'a Value, ctx: &str) -> &'a str {
    value
        .as_str()
        .unwrap_or_else(|| panic!("{ctx} must be a string"))
}

#[test]
fn map_has_required_top_level_shape() {
    let map: Value = serde_json::from_str(MAP_JSON).expect("map JSON must parse");
    let map_obj = as_object(&map, "map");

    assert_eq!(
        as_str(
            map_obj
                .get("schema_version")
                .expect("schema_version is required"),
            "schema_version",
        ),
        "1.0.0"
    );
    assert_eq!(
        as_str(map_obj.get("map_id").expect("map_id is required"), "map_id"),
        "lean.proof_guided_performance_opportunity_map.v1"
    );

    for required in [
        "generated_by",
        "generated_at",
        "source_artifacts",
        "priority_rubric",
        "constraint_catalog",
        "opportunities",
        "consumption_contract",
    ] {
        assert!(map_obj.contains_key(required), "missing field {required}");
    }

    let source_artifacts = as_array(
        map_obj
            .get("source_artifacts")
            .expect("source_artifacts is required"),
        "source_artifacts",
    );
    assert!(
        source_artifacts.len() >= 3,
        "source_artifacts must contain theorem/invariant source references"
    );
}

#[test]
fn priority_rubric_covers_all_bands_in_order() {
    let map: Value = serde_json::from_str(MAP_JSON).expect("map JSON must parse");
    let rubric = as_array(
        map.get("priority_rubric")
            .expect("priority_rubric is required"),
        "priority_rubric",
    );

    assert_eq!(rubric.len(), 4, "expected exactly four priority bands");
    let bands = rubric
        .iter()
        .map(|entry| {
            as_str(
                entry
                    .get("band")
                    .expect("priority_rubric[].band is required"),
                "priority_rubric[].band",
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(bands, vec!["P0", "P1", "P2", "P3"]);

    for entry in rubric {
        let entry_obj = as_object(entry, "priority_rubric[]");
        for required in [
            "expected_impact",
            "proof_coverage_confidence",
            "risk_class",
            "selection_rule",
        ] {
            let value = as_str(
                entry_obj
                    .get(required)
                    .unwrap_or_else(|| panic!("priority_rubric[] missing {required}")),
                "priority_rubric[] field",
            );
            assert!(
                !value.trim().is_empty(),
                "priority_rubric[] field {required} must be non-empty"
            );
        }
    }
}

#[test]
#[allow(clippy::too_many_lines)]
fn opportunities_have_safe_envelopes_and_known_constraints() {
    let map: Value = serde_json::from_str(MAP_JSON).expect("map JSON must parse");

    let constraints = as_array(
        map.get("constraint_catalog")
            .expect("constraint_catalog is required"),
        "constraint_catalog",
    )
    .iter()
    .map(|entry| {
        as_str(
            entry
                .get("constraint_id")
                .expect("constraint_catalog[].constraint_id is required"),
            "constraint_catalog[].constraint_id",
        )
        .to_string()
    })
    .collect::<BTreeSet<_>>();
    assert!(
        constraints.iter().all(|id| id.starts_with("OPT-")),
        "all constraint IDs must use OPT-* naming"
    );

    let opportunities = as_array(
        map.get("opportunities").expect("opportunities is required"),
        "opportunities",
    );
    assert!(
        opportunities.len() >= 4,
        "opportunity map must enumerate at least four envelopes"
    );

    let mut ids = BTreeSet::new();
    let valid_bands = BTreeSet::from(["P0", "P1", "P2", "P3"]);

    for opportunity in opportunities {
        let obj = as_object(opportunity, "opportunities[]");

        let opportunity_id = as_str(
            obj.get("opportunity_id")
                .expect("opportunities[].opportunity_id is required"),
            "opportunities[].opportunity_id",
        );
        assert!(
            ids.insert(opportunity_id.to_string()),
            "duplicate opportunity_id: {opportunity_id}"
        );

        let band = as_str(
            obj.get("priority_band")
                .expect("opportunities[].priority_band is required"),
            "opportunities[].priority_band",
        );
        assert!(
            valid_bands.contains(band),
            "unknown priority band {band} in {opportunity_id}"
        );

        let confidence = as_str(
            obj.get("proof_coverage_confidence")
                .expect("opportunities[].proof_coverage_confidence is required"),
            "opportunities[].proof_coverage_confidence",
        );
        assert!(
            matches!(confidence, "high" | "medium" | "low"),
            "unsupported proof_coverage_confidence {confidence} in {opportunity_id}"
        );

        let target_surface = as_array(
            obj.get("target_surface")
                .expect("opportunities[].target_surface is required"),
            "opportunities[].target_surface",
        );
        assert!(
            !target_surface.is_empty(),
            "target_surface must not be empty in {opportunity_id}"
        );

        let allowed = as_array(
            obj.get("allowed_transformations")
                .expect("opportunities[].allowed_transformations is required"),
            "opportunities[].allowed_transformations",
        )
        .iter()
        .map(|entry| as_str(entry, "allowed_transformations[]").to_string())
        .collect::<BTreeSet<_>>();

        let prohibited = as_array(
            obj.get("prohibited_transformations")
                .expect("opportunities[].prohibited_transformations is required"),
            "opportunities[].prohibited_transformations",
        )
        .iter()
        .map(|entry| as_str(entry, "prohibited_transformations[]").to_string())
        .collect::<BTreeSet<_>>();

        assert!(!allowed.is_empty(), "allowed list must not be empty");
        assert!(!prohibited.is_empty(), "prohibited list must not be empty");
        assert!(
            allowed.is_disjoint(&prohibited),
            "allowed/prohibited overlap in {opportunity_id}"
        );

        let checks = as_array(
            obj.get("required_conformance_checks")
                .expect("opportunities[].required_conformance_checks is required"),
            "opportunities[].required_conformance_checks",
        );
        assert!(!checks.is_empty(), "required checks must not be empty");
        for check in checks {
            let cmd = as_str(check, "required_conformance_checks[]");
            assert!(
                cmd.starts_with("rch exec -- "),
                "all checks must be offloaded through rch: {cmd}"
            );
        }

        let anchors = as_array(
            obj.get("theorem_invariant_anchors")
                .expect("opportunities[].theorem_invariant_anchors is required"),
            "opportunities[].theorem_invariant_anchors",
        );
        assert!(!anchors.is_empty(), "anchors must not be empty");
        for anchor in anchors {
            let anchor_id = as_str(anchor, "theorem_invariant_anchors[]");
            assert!(
                constraints.contains(anchor_id),
                "{opportunity_id} references unknown constraint {anchor_id}"
            );
        }

        let measurements = as_object(
            obj.get("required_measurements")
                .expect("opportunities[].required_measurements is required"),
            "opportunities[].required_measurements",
        );
        for field in ["metrics_before", "metrics_after", "determinism_evidence"] {
            let values = as_array(
                measurements
                    .get(field)
                    .unwrap_or_else(|| panic!("required_measurements missing {field}")),
                "required_measurements.*",
            );
            assert!(
                !values.is_empty(),
                "required_measurements.{field} must not be empty"
            );
        }
    }
}

#[test]
fn bead_links_and_consumption_contract_are_valid() {
    let map: Value = serde_json::from_str(MAP_JSON).expect("map JSON must parse");
    let bead_ids = bead_ids();

    let opportunities = as_array(
        map.get("opportunities").expect("opportunities is required"),
        "opportunities",
    );
    for opportunity in opportunities {
        let obj = as_object(opportunity, "opportunities[]");
        let opportunity_id = as_str(
            obj.get("opportunity_id")
                .expect("opportunities[].opportunity_id is required"),
            "opportunities[].opportunity_id",
        );

        let consumers = as_array(
            obj.get("consumer_beads")
                .expect("opportunities[].consumer_beads is required"),
            "opportunities[].consumer_beads",
        );
        assert!(
            !consumers.is_empty(),
            "consumer_beads must not be empty for {opportunity_id}"
        );
        for bead in consumers {
            let bead_id = as_str(bead, "consumer_beads[]");
            assert!(
                bead_ids.contains(bead_id),
                "{opportunity_id} references unknown bead {bead_id}"
            );
        }
    }

    let contract = as_object(
        map.get("consumption_contract")
            .expect("consumption_contract is required"),
        "consumption_contract",
    );
    let required_template_fields = as_array(
        contract
            .get("required_template_fields")
            .expect("required_template_fields is required"),
        "consumption_contract.required_template_fields",
    );
    assert!(
        required_template_fields.len() >= 8,
        "required_template_fields must include full review payload coverage"
    );

    assert!(
        contract
            .get("must_reference_constraint_ids")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        "must_reference_constraint_ids must be true"
    );
    assert!(
        contract
            .get("must_include_measurement_artifacts")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        "must_include_measurement_artifacts must be true"
    );

    let closed_loop_beads = as_array(
        contract
            .get("closed_loop_consumer_beads")
            .expect("closed_loop_consumer_beads is required"),
        "consumption_contract.closed_loop_consumer_beads",
    );
    assert!(
        !closed_loop_beads.is_empty(),
        "closed_loop_consumer_beads must not be empty"
    );
    for bead in closed_loop_beads {
        let bead_id = as_str(bead, "closed_loop_consumer_beads[]");
        assert!(
            bead_ids.contains(bead_id),
            "unknown closed-loop consumer bead {bead_id}"
        );
    }
}
