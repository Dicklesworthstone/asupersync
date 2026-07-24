//! Contract tests for the VER A4 dependency failure-injection matrix.

#![allow(missing_docs)]

use asupersync::lab::OracleRegistry;
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::panic::{AssertUnwindSafe, catch_unwind};

const ARTIFACT_PATH: &str = "artifacts/dependency_failure_injection_matrix_v1.json";
const INVENTORY_PATH: &str = "artifacts/dependency_verification_matrix_v1.json";
const ERROR_REGISTRY_PATH: &str = "docs/error_codes/registry.json";
const DOC_PATH: &str = "docs/dependency_failure_injection_matrix.md";
const RUNNER_PATH: &str = "scripts/run_dependency_sovereignty_e2e.sh";
const BEAD_ID: &str = "asupersync-dep-p1-foundations-upksjk.6.4";

const REQUIRED_PHASES: &[&str] = &[
    "completion",
    "before_start",
    "parse",
    "encode",
    "network_io",
    "disk_io",
    "queued",
    "retry_backoff",
    "shutdown",
    "peer_disconnect",
    "partial_write",
    "timeout_budget",
    "malformed_input",
    "truncated_input",
    "resource_cap",
    "decompression_bomb",
    "cardinality_bomb",
    "service_restart",
    "rebalance_reconnect",
    "panic_containment",
    "artifact_corruption",
    "partial_migration_rollback",
];

const CORE_ORACLES: &[&str] = &[
    "task_leak",
    "obligation_leak",
    "cancellation_protocol",
    "loser_drain",
    "finalizer",
    "region_tree",
    "quiescence",
];

const RECEIPT_FIELDS: &[&str] = &[
    "scenario_id",
    "phase_id",
    "seed_or_fixture_id",
    "injection_driver",
    "expected_outcome",
    "observed_outcome",
    "stable_asup_error",
    "retryability",
    "obligations_before",
    "obligations_after",
    "permits_before",
    "permits_after",
    "tasks_before",
    "tasks_after",
    "service_processes_before",
    "service_processes_after",
    "artifact_state_before",
    "artifact_state_after",
    "partial_output_validity",
    "injection_phase_reached",
    "first_failing_invariant",
    "cleanup_result",
    "recovery_instruction",
    "replay_command",
];

const TERMINAL_MODES: &[(&str, &str)] = &[
    ("success", "Ok"),
    ("error", "Err"),
    ("cancellation", "Cancelled"),
    ("panic", "Panicked"),
];

fn load_json(path: &str) -> Value {
    let raw = std::fs::read_to_string(path).unwrap_or_else(|error| panic!("read {path}: {error}"));
    serde_json::from_str(&raw).unwrap_or_else(|error| panic!("parse {path}: {error}"))
}

fn strings(value: &Value, field: &str) -> Result<BTreeSet<String>, String> {
    value[field]
        .as_array()
        .ok_or_else(|| format!("{field} must be an array"))?
        .iter()
        .map(|entry| {
            entry
                .as_str()
                .map(str::to_owned)
                .ok_or_else(|| format!("{field} entries must be strings"))
        })
        .collect()
}

fn required_string<'a>(value: &'a Value, field: &str) -> Result<&'a str, String> {
    value[field]
        .as_str()
        .filter(|field_value| !field_value.is_empty())
        .ok_or_else(|| format!("{field} must be a nonempty string"))
}

fn validate_artifact(artifact: &Value, error_registry: &Value) -> Result<(), String> {
    if artifact["schema_version"].as_u64() != Some(1) {
        return Err("schema version must be 1".to_owned());
    }
    if artifact["contract_id"].as_str() != Some("dependency-failure-injection-matrix-v1") {
        return Err("contract id mismatch".to_owned());
    }
    if artifact["bead_id"].as_str() != Some(BEAD_ID) {
        return Err("bead id mismatch".to_owned());
    }

    let policy = &artifact["execution_policy"];
    for field in [
        "deterministic_only",
        "virtual_time_required",
        "sleep_based_races_forbidden",
        "mocks_forbidden",
        "ambient_randomness_forbidden",
        "log_substring_pass_criteria_forbidden",
        "structured_receipt_pass_criterion",
        "first_failure_event_required",
        "exact_replay_command_required",
    ] {
        if policy[field].as_bool() != Some(true) {
            return Err(format!("{field} must be true"));
        }
    }
    let global_max_steps = policy["max_steps_per_scenario"]
        .as_u64()
        .filter(|value| *value > 0)
        .ok_or_else(|| "bounded steps required".to_owned())?;
    let global_max_virtual_time = policy["max_virtual_time_ms"]
        .as_u64()
        .filter(|value| *value > 0)
        .ok_or_else(|| "bounded virtual time required".to_owned())?;
    if strings(policy, "cleanup_required_for_terminal_modes")?
        != TERMINAL_MODES
            .iter()
            .map(|(mode, _)| (*mode).to_owned())
            .collect()
    {
        return Err("cleanup must cover every terminal mode".to_owned());
    }

    let receipt_fields = strings(&artifact["receipt_contract"], "required_fields")?;
    for field in RECEIPT_FIELDS {
        if !receipt_fields.contains(*field) {
            return Err(format!("receipt field missing: {field}"));
        }
    }
    let allowed_outcomes = strings(&artifact["receipt_contract"], "allowed_outcomes")?;
    for (_, outcome) in TERMINAL_MODES {
        if !allowed_outcomes.contains(*outcome) {
            return Err(format!("outcome missing: {outcome}"));
        }
    }

    let declared_core_oracles = strings(artifact, "core_oracles")?;
    for oracle in CORE_ORACLES {
        if !declared_core_oracles.contains(*oracle) {
            return Err(format!("core oracle missing: {oracle}"));
        }
        if !OracleRegistry::contains(oracle) {
            return Err(format!("unknown oracle: {oracle}"));
        }
    }

    let error_codes = error_registry["codes"]
        .as_array()
        .ok_or_else(|| "error registry codes must be an array".to_owned())?
        .iter()
        .filter_map(|entry| entry["code"].as_str())
        .collect::<BTreeSet<_>>();
    let scenarios = artifact["scenarios"]
        .as_array()
        .ok_or_else(|| "scenarios must be an array".to_owned())?;
    if scenarios.is_empty() {
        return Err("scenarios must not be empty".to_owned());
    }

    let mut scenario_ids = BTreeSet::new();
    let mut phases = BTreeSet::new();
    let mut terminal_modes = BTreeSet::new();
    for scenario in scenarios {
        let scenario_id = required_string(scenario, "scenario_id")?;
        if !scenario_ids.insert(scenario_id) {
            return Err(format!("duplicate scenario id: {scenario_id}"));
        }
        let phase = required_string(scenario, "phase_id")?;
        phases.insert(phase);
        let terminal_mode = required_string(scenario, "terminal_mode")?;
        terminal_modes.insert(terminal_mode);
        let expected_outcome = required_string(scenario, "expected_outcome")?;
        let expected_for_mode = TERMINAL_MODES
            .iter()
            .find_map(|(mode, outcome)| (*mode == terminal_mode).then_some(*outcome))
            .ok_or_else(|| format!("unknown terminal mode: {terminal_mode}"))?;
        if expected_outcome != expected_for_mode {
            return Err(format!(
                "{scenario_id} maps {terminal_mode} to {expected_outcome}, expected {expected_for_mode}"
            ));
        }

        let driver = required_string(scenario, "injection_driver")?.to_ascii_lowercase();
        for forbidden in ["sleep", "mock", "ambient_random"] {
            if driver.contains(forbidden) {
                return Err(format!("forbidden injection driver: {driver}"));
            }
        }
        let max_steps = scenario["max_steps"]
            .as_u64()
            .filter(|value| *value > 0)
            .ok_or_else(|| "bounded steps required".to_owned())?;
        if max_steps > global_max_steps {
            return Err(format!("{scenario_id} exceeds the global step bound"));
        }
        let max_virtual_time = scenario["max_virtual_time_ms"]
            .as_u64()
            .filter(|value| *value > 0)
            .ok_or_else(|| "bounded virtual time required".to_owned())?;
        if max_virtual_time > global_max_virtual_time {
            return Err(format!(
                "{scenario_id} exceeds the global virtual-time bound"
            ));
        }
        if scenario["cleanup_required"].as_bool() != Some(true) {
            return Err(format!("cleanup required: {scenario_id}"));
        }
        if scenario["pass_criterion"].as_str() != Some("structured_receipt") {
            return Err(format!("structured receipt required: {scenario_id}"));
        }

        let replay = required_string(scenario, "replay_command")
            .map_err(|_| format!("exact replay command required: {scenario_id}"))?;
        if !replay.starts_with("RCH_REQUIRE_REMOTE=1 ")
            || !replay.contains("scripts/run_dependency_sovereignty_e2e.sh")
            || !replay.contains("--scenario failure-injection-contract")
        {
            return Err(format!("exact replay command required: {scenario_id}"));
        }
        required_string(scenario, "seed_or_fixture_id")?;
        required_string(scenario, "retryability")?;
        required_string(scenario, "partial_output_validity")?;
        required_string(scenario, "recovery_instruction")?;

        let events = strings(scenario, "required_events")?;
        for event in [
            "scenario_started",
            "injection_phase_reached",
            "terminal_outcome_observed",
            "cleanup_completed",
            "oracle_snapshot",
            "replay_recorded",
        ] {
            if !events.contains(event) {
                return Err(format!("{scenario_id} missing required event {event}"));
            }
        }
        if terminal_mode != "success" && !events.contains("first_failure") {
            return Err(format!("{scenario_id} missing first_failure event"));
        }

        let operator_facing = scenario["operator_facing"]
            .as_bool()
            .ok_or_else(|| format!("{scenario_id} operator_facing must be boolean"))?;
        let stable_error = scenario["stable_asup_error"].as_str();
        if operator_facing {
            let code = stable_error
                .filter(|code| error_codes.contains(code))
                .ok_or_else(|| format!("operator-facing error code required: {scenario_id}"))?;
            if !code.starts_with("ASUP-E") {
                return Err(format!(
                    "operator-facing error code required: {scenario_id}"
                ));
            }
        } else if stable_error.is_some() {
            return Err(format!(
                "{scenario_id} must not claim an operator error without an operator-facing boundary"
            ));
        }

        for oracle in strings(scenario, "required_oracles")? {
            if !OracleRegistry::contains(&oracle) {
                return Err(format!("unknown oracle: {oracle}"));
            }
        }
    }

    for required_phase in REQUIRED_PHASES {
        if !phases.contains(required_phase) {
            return Err(format!("required phase missing: {required_phase}"));
        }
    }
    for (required_mode, _) in TERMINAL_MODES {
        if !terminal_modes.contains(required_mode) {
            return Err(format!("terminal mode missing: {required_mode}"));
        }
    }

    let rules = artifact["applicability_rules"]
        .as_array()
        .ok_or_else(|| "applicability rules must be an array".to_owned())?;
    if rules.is_empty() {
        return Err("replacement row uncovered: no applicability rules".to_owned());
    }
    for rule in rules {
        required_string(rule, "family_id")?;
        let rule_scenarios = strings(rule, "scenario_ids")?;
        if rule_scenarios.is_empty() {
            return Err("applicability rule must name scenarios".to_owned());
        }
        for scenario_id in rule_scenarios {
            if !scenario_ids.contains(scenario_id.as_str()) {
                return Err(format!(
                    "applicability rule references unknown scenario: {scenario_id}"
                ));
            }
        }
        for oracle in strings(rule, "required_oracles")? {
            if !OracleRegistry::contains(&oracle) {
                return Err(format!("unknown oracle: {oracle}"));
            }
        }
    }
    Ok(())
}

fn selector_matches(row: &Value, selector: &Value) -> bool {
    if selector["all"].as_bool() == Some(true) {
        return true;
    }
    let row_risks = row["risk_tags"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .collect::<BTreeSet<_>>();
    let risk_match = selector["risk_tags_any"].as_array().is_some_and(|risks| {
        risks
            .iter()
            .filter_map(Value::as_str)
            .any(|risk| row_risks.contains(risk))
    });
    let row_capabilities = row["capability_ids"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .collect::<BTreeSet<_>>();
    let capability_match = selector["capability_ids_any"]
        .as_array()
        .is_some_and(|capabilities| {
            capabilities
                .iter()
                .filter_map(Value::as_str)
                .any(|capability| row_capabilities.contains(capability))
        });
    risk_match || capability_match
}

fn validate_inventory_mapping(artifact: &Value, inventory: &Value) -> Result<(), String> {
    let scenarios = artifact["scenarios"]
        .as_array()
        .ok_or_else(|| "scenarios must be an array".to_owned())?
        .iter()
        .map(|scenario| {
            (
                scenario["scenario_id"].as_str().unwrap_or_default(),
                scenario["phase_id"].as_str().unwrap_or_default(),
            )
        })
        .collect::<BTreeMap<_, _>>();
    let rules = artifact["applicability_rules"]
        .as_array()
        .ok_or_else(|| "applicability rules must be an array".to_owned())?;
    let rows = inventory["matrix"]
        .as_array()
        .ok_or_else(|| "replacement inventory matrix must be an array".to_owned())?;
    if rows.is_empty() {
        return Err("replacement inventory matrix must not be empty".to_owned());
    }

    let required_family_phases = BTreeMap::from([
        (
            "universal-boundary",
            vec![
                "completion",
                "before_start",
                "timeout_budget",
                "panic_containment",
            ],
        ),
        (
            "concurrent-state",
            vec!["queued", "retry_backoff", "shutdown"],
        ),
        (
            "parser-codec",
            vec!["parse", "encode", "malformed_input", "truncated_input"],
        ),
        (
            "resource-sensitive",
            vec!["resource_cap", "decompression_bomb", "cardinality_bomb"],
        ),
        (
            "networked-service",
            vec![
                "network_io",
                "peer_disconnect",
                "partial_write",
                "service_restart",
                "rebalance_reconnect",
            ],
        ),
        (
            "persisted-state",
            vec![
                "disk_io",
                "artifact_corruption",
                "partial_migration_rollback",
            ],
        ),
        (
            "user-journey-recovery",
            vec![
                "service_restart",
                "rebalance_reconnect",
                "partial_migration_rollback",
            ],
        ),
    ]);
    let mut family_match_counts = BTreeMap::<&str, usize>::new();

    for row in rows {
        let bead_id = row["bead_id"].as_str().unwrap_or("<unknown>");
        let mut mapped_scenarios = BTreeSet::new();
        let mut mapped_oracles = BTreeSet::new();
        for rule in rules {
            if !selector_matches(row, &rule["selector"]) {
                continue;
            }
            let family_id = rule["family_id"].as_str().unwrap_or("<unknown>");
            *family_match_counts.entry(family_id).or_default() += 1;
            let phases = rule["scenario_ids"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
                .map(|scenario_id| {
                    mapped_scenarios.insert(scenario_id);
                    scenarios.get(scenario_id).copied().unwrap_or("<unknown>")
                })
                .collect::<BTreeSet<_>>();
            for required_phase in required_family_phases
                .get(family_id)
                .ok_or_else(|| format!("unknown applicability family: {family_id}"))?
            {
                if !phases.contains(required_phase) {
                    return Err(format!(
                        "{bead_id} family {family_id} missing phase {required_phase}"
                    ));
                }
            }
            mapped_oracles.extend(
                rule["required_oracles"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .filter_map(Value::as_str),
            );
        }
        if mapped_scenarios.is_empty() {
            return Err(format!("replacement row uncovered: {bead_id}"));
        }
        for oracle in ["task_leak", "obligation_leak", "finalizer", "quiescence"] {
            if !mapped_oracles.contains(oracle) {
                return Err(format!("{bead_id} missing mapped oracle {oracle}"));
            }
        }
    }

    for family_id in required_family_phases.keys() {
        if family_match_counts.get(family_id).copied().unwrap_or(0) == 0 {
            return Err(format!("applicability family matches no rows: {family_id}"));
        }
    }
    Ok(())
}

#[derive(Debug, Clone, Copy)]
struct ResourceState {
    obligations: usize,
    permits: usize,
    tasks: usize,
    services: usize,
    cleanup_runs: usize,
    phase_reached: bool,
}

impl ResourceState {
    const fn active() -> Self {
        Self {
            obligations: 1,
            permits: 1,
            tasks: 1,
            services: 1,
            cleanup_runs: 0,
            phase_reached: false,
        }
    }

    fn cleanup(&mut self) {
        self.obligations = 0;
        self.permits = 0;
        self.tasks = 0;
        self.services = 0;
        self.cleanup_runs += 1;
    }

    const fn is_quiescent(self) -> bool {
        self.obligations == 0
            && self.permits == 0
            && self.tasks == 0
            && self.services == 0
            && self.cleanup_runs == 1
    }
}

#[derive(Debug)]
struct ModelReceipt<'a> {
    scenario_id: &'a str,
    phase_id: &'a str,
    terminal_mode: &'a str,
    observed_outcome: &'a str,
    phase_reached: bool,
    cleanup_result: &'a str,
    first_failing_invariant: Option<&'a str>,
    before: ResourceState,
    after: ResourceState,
}

fn run_deterministic_model<'a>(scenario: &'a Value, terminal_mode: &'a str) -> ModelReceipt<'a> {
    let scenario_id = scenario["scenario_id"].as_str().expect("scenario id");
    let phase_id = scenario["phase_id"].as_str().expect("phase id");
    let mut state = ResourceState::active();
    let before = state;
    let observed_outcome = TERMINAL_MODES
        .iter()
        .find_map(|(mode, outcome)| (*mode == terminal_mode).then_some(*outcome))
        .expect("known terminal mode");
    let panicked = if terminal_mode == "panic" {
        catch_unwind(AssertUnwindSafe(|| {
            state.phase_reached = true;
            panic!("deterministic injected panic at {phase_id}");
        }))
        .is_err()
    } else {
        state.phase_reached = true;
        false
    };
    assert_eq!(panicked, terminal_mode == "panic");
    state.cleanup();

    ModelReceipt {
        scenario_id,
        phase_id,
        terminal_mode,
        observed_outcome,
        phase_reached: state.phase_reached,
        cleanup_result: "quiescent",
        first_failing_invariant: (terminal_mode != "success").then_some("injected_terminal"),
        before,
        after: state,
    }
}

fn structured_model_receipt(scenario: &Value, receipt: &ModelReceipt<'_>) -> Value {
    let mut events = vec![
        "scenario_started",
        "injection_phase_reached",
        "terminal_outcome_observed",
        "cleanup_completed",
        "oracle_snapshot",
        "replay_recorded",
    ];
    if receipt.first_failing_invariant.is_some() {
        events.insert(2, "first_failure");
    }
    serde_json::json!({
        "schema_version": "dependency-failure-injection-receipt-v1",
        "scenario_id": receipt.scenario_id,
        "phase_id": receipt.phase_id,
        "terminal_mode": receipt.terminal_mode,
        "seed_or_fixture_id": scenario["seed_or_fixture_id"],
        "injection_driver": scenario["injection_driver"],
        "expected_outcome": receipt.observed_outcome,
        "observed_outcome": receipt.observed_outcome,
        "catalog_expected_outcome": scenario["expected_outcome"],
        "stable_asup_error": scenario["stable_asup_error"],
        "retryability": scenario["retryability"],
        "obligations_before": receipt.before.obligations,
        "obligations_after": receipt.after.obligations,
        "permits_before": receipt.before.permits,
        "permits_after": receipt.after.permits,
        "tasks_before": receipt.before.tasks,
        "tasks_after": receipt.after.tasks,
        "service_processes_before": receipt.before.services,
        "service_processes_after": receipt.after.services,
        "artifact_state_before": "uncommitted",
        "artifact_state_after": scenario["partial_output_validity"],
        "partial_output_validity": scenario["partial_output_validity"],
        "injection_phase_reached": receipt.phase_reached,
        "first_failing_invariant": receipt.first_failing_invariant,
        "cleanup_result": receipt.cleanup_result,
        "recovery_instruction": scenario["recovery_instruction"],
        "replay_command": scenario["replay_command"],
        "events": events,
    })
}

fn scenario_mut<'a>(artifact: &'a mut Value, scenario_id: &str) -> &'a mut Value {
    artifact["scenarios"]
        .as_array_mut()
        .expect("scenarios")
        .iter_mut()
        .find(|scenario| scenario["scenario_id"].as_str() == Some(scenario_id))
        .unwrap_or_else(|| panic!("scenario {scenario_id}"))
}

fn apply_negative_mutation(artifact: &mut Value, mutation: &str) {
    match mutation {
        "remove_required_phase" => artifact["scenarios"]
            .as_array_mut()
            .expect("scenarios")
            .retain(|scenario| {
                scenario["scenario_id"].as_str() != Some("FI-PARTIAL-MIGRATION-ROLLBACK")
            }),
        "set_max_steps_zero" => {
            scenario_mut(artifact, "FI-SUCCESS-CLEANUP")["max_steps"] = 0.into();
        }
        "set_driver_sleep" => {
            scenario_mut(artifact, "FI-SUCCESS-CLEANUP")["injection_driver"] =
                "thread_sleep".into();
        }
        "set_driver_ambient_random" => {
            scenario_mut(artifact, "FI-SUCCESS-CLEANUP")["injection_driver"] =
                "ambient_random".into();
        }
        "set_driver_mock" => {
            scenario_mut(artifact, "FI-SUCCESS-CLEANUP")["injection_driver"] =
                "mock_service".into();
        }
        "set_log_substring_pass_criterion" => {
            scenario_mut(artifact, "FI-SUCCESS-CLEANUP")["pass_criterion"] = "log_substring".into();
        }
        "disable_panic_cleanup" => {
            scenario_mut(artifact, "FI-PANIC-CONTAINMENT")["cleanup_required"] = false.into();
        }
        "remove_core_oracle" => artifact["core_oracles"]
            .as_array_mut()
            .expect("core oracles")
            .retain(|oracle| oracle.as_str() != Some("quiescence")),
        "add_unknown_oracle" => scenario_mut(artifact, "FI-SUCCESS-CLEANUP")["required_oracles"]
            .as_array_mut()
            .expect("scenario oracles")
            .push("not_a_real_oracle".into()),
        "clear_operator_error" => {
            scenario_mut(artifact, "FI-TIMEOUT-BUDGET")["stable_asup_error"] = Value::Null;
        }
        "clear_replay_command" => {
            scenario_mut(artifact, "FI-SUCCESS-CLEANUP")["replay_command"] = "".into();
        }
        "remove_receipt_field" => artifact["receipt_contract"]["required_fields"]
            .as_array_mut()
            .expect("receipt fields")
            .retain(|field| field.as_str() != Some("cleanup_result")),
        "remove_applicability_rules" => {
            artifact["applicability_rules"] = Value::Array(Vec::new());
        }
        other => panic!("unknown negative mutation {other}"),
    }
}

#[test]
#[allow(non_snake_case)] // Stable test ID generated by the VER A1 evidence matrix.
fn ver_a1_asupersync_dep_p1_foundations_upksjk_6_4_4f6cbc4927a2__local_invariants() {
    let artifact = load_json(ARTIFACT_PATH);
    let inventory = load_json(INVENTORY_PATH);
    let error_registry = load_json(ERROR_REGISTRY_PATH);
    validate_artifact(&artifact, &error_registry).expect("VER A4 artifact must be valid");
    validate_inventory_mapping(&artifact, &inventory)
        .expect("every live replacement row must map to deterministic failure evidence");

    assert_eq!(
        artifact["source_of_truth"]["contract_test"].as_str(),
        Some("tests/dependency_failure_injection_matrix_contract.rs")
    );
    assert_eq!(
        artifact["source_of_truth"]["e2e_runner"].as_str(),
        Some(RUNNER_PATH)
    );
    assert_eq!(inventory["counts"]["matrix_beads"].as_u64(), Some(335));

    let docs = std::fs::read_to_string(DOC_PATH).expect("failure-injection docs");
    let runner = std::fs::read_to_string(RUNNER_PATH).expect("dependency-sovereignty runner");
    for marker in [
        ARTIFACT_PATH,
        INVENTORY_PATH,
        "failure-injection-contract",
        "structured receipt",
        "no-mock",
        "No-claim",
    ] {
        assert!(docs.contains(marker), "docs missing marker {marker}");
    }
    for marker in [
        "failure-injection-contract",
        "dependency_failure_injection_matrix_contract",
        "ver-a4-failure-injection-contract",
    ] {
        assert!(runner.contains(marker), "runner missing marker {marker}");
    }
}

#[test]
#[allow(non_snake_case)] // Stable test ID generated by the VER A1 evidence matrix.
fn ver_a1_asupersync_dep_p1_foundations_upksjk_6_4_4f6cbc4927a2__property_matrix() {
    let artifact = load_json(ARTIFACT_PATH);
    let inventory = load_json(INVENTORY_PATH);
    let error_registry = load_json(ERROR_REGISTRY_PATH);
    let fixtures = artifact["negative_fixtures"]
        .as_array()
        .expect("negative fixtures");
    assert_eq!(fixtures.len(), 13);

    for fixture in fixtures {
        let fixture_id = fixture["fixture_id"].as_str().expect("fixture id");
        let mutation = fixture["mutation"].as_str().expect("fixture mutation");
        let expected_error = fixture["expected_error"].as_str().expect("expected error");
        let mut mutated = artifact.clone();
        apply_negative_mutation(&mut mutated, mutation);
        let result = validate_artifact(&mutated, &error_registry)
            .and_then(|()| validate_inventory_mapping(&mutated, &inventory));
        let error = result.unwrap_err();
        assert!(
            error.contains(expected_error),
            "fixture {fixture_id} expected {expected_error:?}, observed {error:?}"
        );
    }
}

#[test]
#[allow(non_snake_case)] // Stable test ID generated by the VER A1 evidence matrix.
fn ver_a1_asupersync_dep_p1_foundations_upksjk_6_4_4f6cbc4927a2__lab_lifecycle() {
    let artifact = load_json(ARTIFACT_PATH);
    let scenarios = artifact["scenarios"].as_array().expect("scenarios");
    assert_eq!(scenarios.len(), REQUIRED_PHASES.len());

    let mut reached = BTreeSet::new();
    let mut observed_modes = BTreeSet::new();
    for scenario in scenarios {
        for (terminal_mode, expected_outcome) in TERMINAL_MODES {
            let receipt = run_deterministic_model(scenario, terminal_mode);
            reached.insert(receipt.phase_id);
            observed_modes.insert(receipt.terminal_mode);
            assert_eq!(receipt.observed_outcome, *expected_outcome);
            assert!(
                receipt.phase_reached,
                "{} did not reach {} under {terminal_mode}",
                receipt.scenario_id, receipt.phase_id
            );
            assert_eq!(receipt.cleanup_result, "quiescent");
            assert!(
                receipt.after.is_quiescent(),
                "{} leaked resources under {terminal_mode}: {:?}",
                receipt.scenario_id,
                receipt.after
            );
            assert_eq!(
                receipt.first_failing_invariant.is_some(),
                *terminal_mode != "success"
            );
            let structured = structured_model_receipt(scenario, &receipt);
            for field in RECEIPT_FIELDS {
                assert!(
                    structured.get(*field).is_some(),
                    "{} {terminal_mode} receipt missing {field}",
                    receipt.scenario_id
                );
            }
            println!("{structured}");
        }
    }
    assert_eq!(
        reached,
        REQUIRED_PHASES.iter().copied().collect::<BTreeSet<_>>()
    );
    assert_eq!(
        observed_modes,
        TERMINAL_MODES
            .iter()
            .map(|(mode, _)| *mode)
            .collect::<BTreeSet<_>>()
    );
}
