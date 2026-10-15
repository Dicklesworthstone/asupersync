#![allow(missing_docs)]

use serde_json::{Value, json};
use std::collections::BTreeSet;
use std::path::Path;

const CONTRACT_PATH: &str = "artifacts/tokio_migration_shadow_workload_contract_v1.json";

const REQUIRED_CLASSES: &[&str] = &[
    "mpsc-backpressure",
    "select-timeout-race",
    "broadcast-fanout",
    "spawn-join-ownership",
    "mutex-contention",
    "blocking-work",
    "graceful-shutdown",
];

const SUPPORTED_IDIOMS: &[&str] = &[
    "tokio_mpsc_reserve_send",
    "tokio_select_timeout_race",
    "tokio_broadcast_watch_fanout",
    "tokio_spawn_join_handle",
    "tokio_mutex_semaphore_contention",
    "tokio_spawn_blocking",
    "tokio_signal_shutdown",
];

const REQUIRED_INVARIANTS: &[&str] = &[
    "no_obligation_leak",
    "losers_drained",
    "no_orphan_tasks",
    "region_close_quiescence",
];

fn load_contract() -> Value {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(CONTRACT_PATH);
    let text = std::fs::read_to_string(path).expect("migration shadow workload contract exists");
    serde_json::from_str(&text).expect("migration shadow workload contract parses as JSON")
}

fn scenarios(contract: &Value) -> &[Value] {
    contract["scenarios"]
        .as_array()
        .expect("scenarios must be an array")
}

fn string_field<'a>(value: &'a Value, field: &str) -> Result<&'a str, String> {
    value
        .get(field)
        .and_then(Value::as_str)
        .filter(|text| !text.is_empty())
        .ok_or_else(|| format!("missing required string field {field}"))
}

fn array_field<'a>(value: &'a Value, field: &str) -> Result<&'a Vec<Value>, String> {
    value
        .get(field)
        .and_then(Value::as_array)
        .filter(|items| !items.is_empty())
        .ok_or_else(|| format!("missing required array field {field}"))
}

fn validate_contract(contract: &Value) -> Result<(), String> {
    for field in [
        "contract_version",
        "schema_version",
        "generated_for_bead",
        "purpose",
        "proxy_evidence_policy",
        "unsupported_idiom_policy",
        "determinism_policy",
        "workload_scale_limits",
        "required_scenario_classes",
        "required_report_fields",
        "scenarios",
    ] {
        if contract.get(field).is_none() {
            return Err(format!("missing top-level field {field}"));
        }
    }

    if contract["proxy_evidence_policy"] != "reject" {
        return Err("proxy_evidence_policy must be reject".to_string());
    }
    if contract["unsupported_idiom_policy"] != "fail_closed" {
        return Err("unsupported_idiom_policy must be fail_closed".to_string());
    }

    let scale_limits = contract
        .get("workload_scale_limits")
        .ok_or_else(|| "missing workload_scale_limits".to_string())?;
    let max_tasks = scale_limits["small_mode_max_tasks"]
        .as_u64()
        .ok_or_else(|| "small_mode_max_tasks must be numeric".to_string())?;
    let max_channels = scale_limits["small_mode_max_channels"]
        .as_u64()
        .ok_or_else(|| "small_mode_max_channels must be numeric".to_string())?;

    let mut scenario_ids = BTreeSet::new();
    for scenario in scenarios(contract) {
        for field in [
            "scenario_id",
            "scenario_class",
            "tokio_idiom",
            "tokio_source_surface",
            "asupersync_rewrite",
            "asupersync_contract_surface",
            "deterministic_seed",
            "workload_scale",
            "cancellation_injection_points",
            "expected_asupersync_invariants",
            "evidence_policy",
            "operator_note_template",
        ] {
            if scenario.get(field).is_none() {
                return Err(format!("scenario missing field {field}"));
            }
        }

        let scenario_id = string_field(scenario, "scenario_id")?;
        if !scenario_id.starts_with("TM-SHADOW-") {
            return Err(format!("unstable scenario id {scenario_id}"));
        }
        if !scenario_ids.insert(scenario_id.to_string()) {
            return Err(format!("duplicate scenario id {scenario_id}"));
        }

        let idiom = string_field(scenario, "tokio_idiom")?;
        if !SUPPORTED_IDIOMS.contains(&idiom) {
            return Err(format!("unsupported Tokio idiom {idiom}"));
        }

        let seed = string_field(scenario, "deterministic_seed")?;
        let hex = seed
            .strip_prefix("0x")
            .ok_or_else(|| format!("seed {seed} must use 0x prefix"))?;
        u64::from_str_radix(hex, 16).map_err(|_| format!("seed {seed} must parse as hex u64"))?;

        let workload_scale = scenario
            .get("workload_scale")
            .ok_or_else(|| "missing workload_scale".to_string())?;
        let small_tasks = workload_scale["small_mode_tasks"]
            .as_u64()
            .ok_or_else(|| "small_mode_tasks must be numeric".to_string())?;
        let small_channels = workload_scale["small_mode_channels"]
            .as_u64()
            .ok_or_else(|| "small_mode_channels must be numeric".to_string())?;
        if small_tasks == 0 || small_tasks > max_tasks {
            return Err(format!("small_mode_tasks {small_tasks} out of bounds"));
        }
        if small_channels == 0 || small_channels > max_channels {
            return Err(format!(
                "small_mode_channels {small_channels} out of bounds"
            ));
        }

        array_field(scenario, "cancellation_injection_points")?;
        array_field(scenario, "expected_asupersync_invariants")?;

        let note = string_field(scenario, "operator_note_template")?;
        for forbidden in ["password", "secret=", "token=", "private_key"] {
            if note.to_ascii_lowercase().contains(forbidden) {
                return Err(format!(
                    "operator note contains unredacted token {forbidden}"
                ));
            }
        }

        let evidence_policy = scenario
            .get("evidence_policy")
            .ok_or_else(|| "missing evidence_policy".to_string())?;
        if evidence_policy["reference_mode"] != "canonical_tokio_boundary" {
            return Err("reference_mode must use canonical_tokio_boundary".to_string());
        }
        if evidence_policy["proxy_evidence_allowed"] != false {
            return Err("proxy evidence must be rejected".to_string());
        }
        if evidence_policy["artifact_paths_required"] != true {
            return Err("artifact paths must be required".to_string());
        }
    }

    Ok(())
}

#[test]
fn contract_exists_and_declares_fail_closed_policies() {
    let contract = load_contract();

    assert_eq!(
        contract["contract_version"],
        "tokio-migration-shadow-workload-v1"
    );
    assert_eq!(
        contract["schema_version"],
        "tokio-migration-shadow-workload-schema-v1"
    );
    assert_eq!(contract["generated_for_bead"], "asupersync-tokmap");
    assert_eq!(contract["proxy_evidence_policy"], "reject");
    assert_eq!(contract["unsupported_idiom_policy"], "fail_closed");
    validate_contract(&contract).expect("contract should validate");
}

#[test]
fn required_scenario_classes_are_present() {
    let contract = load_contract();
    let classes: BTreeSet<_> = scenarios(&contract)
        .iter()
        .map(|scenario| string_field(scenario, "scenario_class").unwrap())
        .collect();

    for required in REQUIRED_CLASSES {
        assert!(
            classes.contains(required),
            "missing scenario class {required}; found {classes:?}"
        );
    }
}

#[test]
fn scenario_ids_are_unique_stable_and_lexically_ordered() {
    let contract = load_contract();
    let ids: Vec<_> = scenarios(&contract)
        .iter()
        .map(|scenario| string_field(scenario, "scenario_id").unwrap())
        .collect();
    let mut sorted = ids.clone();
    sorted.sort_unstable();

    assert_eq!(ids, sorted, "scenario IDs must be stored in lexical order");
    assert_eq!(
        ids.len(),
        ids.iter().collect::<BTreeSet<_>>().len(),
        "scenario IDs must be unique"
    );
}

#[test]
fn deterministic_seeds_parse_as_hex_u64() {
    let contract = load_contract();

    for scenario in scenarios(&contract) {
        let seed = string_field(scenario, "deterministic_seed").unwrap();
        let hex = seed.strip_prefix("0x").expect("seed has 0x prefix");
        let parsed = u64::from_str_radix(hex, 16).expect("seed parses as hex u64");
        assert_ne!(parsed, 0, "seed must not be zero for {seed}");
    }
}

#[test]
fn small_mode_workloads_are_bounded() {
    let contract = load_contract();
    let limits = &contract["workload_scale_limits"];
    let max_tasks = limits["small_mode_max_tasks"].as_u64().unwrap();
    let max_channels = limits["small_mode_max_channels"].as_u64().unwrap();

    for scenario in scenarios(&contract) {
        let scale = &scenario["workload_scale"];
        let tasks = scale["small_mode_tasks"].as_u64().unwrap();
        let channels = scale["small_mode_channels"].as_u64().unwrap();
        assert!(
            (1..=max_tasks).contains(&tasks),
            "small task count {tasks} out of bounds"
        );
        assert!(
            (1..=max_channels).contains(&channels),
            "small channel count {channels} out of bounds"
        );
    }
}

#[test]
fn every_scenario_names_cancellation_points_and_invariants() {
    let contract = load_contract();
    let mut seen_invariants = BTreeSet::new();

    for scenario in scenarios(&contract) {
        assert!(
            array_field(scenario, "cancellation_injection_points")
                .unwrap()
                .len()
                >= 3,
            "each scenario needs at least three cancellation injection points"
        );
        for invariant in array_field(scenario, "expected_asupersync_invariants").unwrap() {
            seen_invariants.insert(invariant.as_str().expect("invariant is string"));
        }
    }

    for invariant in REQUIRED_INVARIANTS {
        assert!(
            seen_invariants.contains(invariant),
            "required invariant {invariant} is not represented"
        );
    }
}

#[test]
fn operator_notes_are_redacted_and_proxy_evidence_is_rejected() {
    let contract = load_contract();

    for scenario in scenarios(&contract) {
        let note = string_field(scenario, "operator_note_template").unwrap();
        assert!(
            note.contains("redacted"),
            "operator note should explicitly name redaction: {note}"
        );
        assert_eq!(
            scenario["evidence_policy"]["proxy_evidence_allowed"], false,
            "proxy evidence must be rejected"
        );
        assert_eq!(
            scenario["evidence_policy"]["artifact_paths_required"], true,
            "artifact paths must be required"
        );
    }
}

#[test]
fn validator_rejects_missing_required_fields() {
    let mut contract = load_contract();
    contract
        .as_object_mut()
        .unwrap()
        .remove("required_report_fields");

    let err = validate_contract(&contract).expect_err("missing field must be rejected");
    assert!(
        err.contains("required_report_fields"),
        "unexpected error: {err}"
    );
}

#[test]
fn validator_rejects_unsupported_tokio_idiom() {
    let mut contract = load_contract();
    contract["scenarios"][0]["tokio_idiom"] = json!("tokio_unstructured_global_spawn");

    let err = validate_contract(&contract).expect_err("unsupported idiom must be rejected");
    assert!(
        err.contains("unsupported Tokio idiom"),
        "unexpected error: {err}"
    );
}

#[test]
fn validator_rejects_unbounded_small_mode_scale() {
    let mut contract = load_contract();
    contract["scenarios"][0]["workload_scale"]["small_mode_tasks"] = json!(999_999_u64);

    let err = validate_contract(&contract).expect_err("unbounded small mode must be rejected");
    assert!(err.contains("small_mode_tasks"), "unexpected error: {err}");
}

#[test]
fn validator_rejects_unredacted_operator_notes() {
    let mut contract = load_contract();
    contract["scenarios"][0]["operator_note_template"] =
        json!("operator supplied token=abc123 for reproduction");

    let err = validate_contract(&contract).expect_err("unredacted note must be rejected");
    assert!(err.contains("unredacted"), "unexpected error: {err}");
}

#[test]
fn validator_rejects_proxy_evidence() {
    let mut contract = load_contract();
    contract["scenarios"][0]["evidence_policy"]["proxy_evidence_allowed"] = json!(true);

    let err = validate_contract(&contract).expect_err("proxy evidence must be rejected");
    assert!(err.contains("proxy evidence"), "unexpected error: {err}");
}
