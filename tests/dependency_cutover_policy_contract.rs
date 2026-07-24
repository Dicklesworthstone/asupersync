#![allow(missing_docs)]

//! Fail-closed contract for the CAP A3 dependency cutover policy.
//!
//! Fixture: `artifacts/dependency_cutover_policy_v1.json`
//! Bead: `asupersync-dep-p1-foundations-upksjk.5.3`

use serde_json::{Map, Value, json};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::path::{Path, PathBuf};

const ARTIFACT_PATH: &str = "artifacts/dependency_cutover_policy_v1.json";
const REGISTRY_PATH: &str = "artifacts/dependency_capability_registry_v1.json";
const BASELINE_PATH: &str = "artifacts/dependency_capability_baseline_v1.json";
const ORACLE_PATH: &str = "artifacts/dependency_oracle_policy_v1.json";
const TAXONOMY_PATH: &str = "artifacts/dependency_safety_taxonomy_v1.json";
const LEDGER_PATH: &str = "artifacts/dependency_marginal_ledger_v1.json";
const GOVERNANCE_LEDGER_PATH: &str = "artifacts/artifact_governance_ledger_v1.json";
const DOC_PATH: &str = "docs/dependency_cutover_policy.md";
const RUNNER_PATH: &str = "scripts/run_dependency_cutover_policy.sh";
const TEST_PATH: &str = "tests/dependency_cutover_policy_contract.rs";
const BEADS_PATH: &str = ".beads/issues.jsonl";
const BEAD_ID: &str = "asupersync-dep-p1-foundations-upksjk.5.3";
const PROGRAM_ID: &str = "asupersync-ir2uf0";

const TERMINAL_VERDICTS: &[&str] = &["BLOCKED", "DEFER", "KEEP", "REPLACE"];
const PARITY_RESULTS: &[&str] = &["BETTER", "NOT_APPLICABLE", "SAME", "UNKNOWN", "WORSE"];
const EVIDENCE_OUTCOMES: &[&str] = &[
    "BLOCKED_EXTERNAL",
    "BLOCKED_OWNER",
    "BLOCKED_PLATFORM",
    "FAIL",
    "NO_WIN",
    "PASS",
    "UNSUPPORTED",
];
const BINDING_ROLES: &[&str] = &["CUTOVER_TARGET", "GUARD_ONLY"];
const REQUIRED_CASE_CLASSES: &[&str] = &[
    "cancellation_cleanup",
    "empty_boundary",
    "malformed_error",
    "positive",
    "recovery",
    "resource_limit",
];
const REQUIRED_GLOBAL_GATES: &[&str] = &[
    "GATE-BASELINE-FRESHNESS",
    "GATE-CAPABILITY-MAP",
    "GATE-DOWNSTREAM",
    "GATE-E2E",
    "GATE-FINAL-NO-LOSS",
    "GATE-MARGINAL-GRAPH",
    "GATE-ORACLE",
    "GATE-OWNER",
    "GATE-ROLLBACK",
    "GATE-SAFETY",
    "GATE-UNIT-INVARIANTS",
    "GATE-UX-DOCS",
];
const REQUIRED_MIGRATION_CLASSES: &[&str] = &[
    "CLI_OPERATOR",
    "CONCURRENCY_PERFORMANCE",
    "CONFIG_LANGUAGE",
    "DOWNSTREAM_RELOCATION",
    "GUARD_ONLY",
    "OPERATOR_UX",
    "PLATFORM_BOUNDARY",
    "SECURITY_SENSITIVE",
    "SERVICE_INTEROP",
    "SOURCE_API",
    "STATEFUL_RUNTIME",
    "STATELESS_SEMANTIC",
    "VERIFICATION_INFRASTRUCTURE",
    "VERSIONED_DATA",
    "WIRE_PROTOCOL",
];
const REQUIRED_STATES: &[&str] = &[
    "COEXISTENCE",
    "CUTOVER_CANDIDATE",
    "DEPENDENCY_EXITED",
    "DEPENDENCY_EXIT_PENDING",
    "INCUMBENT_PRIMARY",
    "INCUMBENT_RESTORED",
    "PROTOTYPE_ISOLATED",
    "REPLACEMENT_PRIMARY",
    "ROLLBACK_ACTIVE",
    "SHADOW",
];
const DECISION_RECEIPT_FIELDS: &[&str] = &[
    "affected_capability_ids",
    "api_narrowing",
    "blocking_owners",
    "campaign_close_requested",
    "candidate_id",
    "case_results",
    "decision_reason",
    "documentation_receipt",
    "downstream_receipts",
    "evidence_as_of_utc",
    "feature_loss",
    "format_rejection",
    "gate_results",
    "incumbent_action",
    "migration_plan",
    "no_claim_boundaries",
    "oracle_disposition",
    "owner_signoffs",
    "parity_results",
    "performance_review",
    "platform_matrix",
    "production_switch_requested",
    "requested_verdict",
    "resume_conditions",
    "rollback_plan",
    "security_review",
    "service_matrix",
    "source_revision",
    "state_transition",
    "unresolved_regressions",
];

fn repo_path(relative: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(relative)
}

fn read_repo_file(relative: &str) -> String {
    std::fs::read_to_string(repo_path(relative))
        .unwrap_or_else(|error| panic!("read {relative}: {error}"))
}

fn parse_repo_json(relative: &str) -> Value {
    serde_json::from_str(&read_repo_file(relative))
        .unwrap_or_else(|error| panic!("parse {relative}: {error}"))
}

fn policy() -> Value {
    parse_repo_json(ARTIFACT_PATH)
}

fn registry() -> Value {
    parse_repo_json(REGISTRY_PATH)
}

fn baseline() -> Value {
    parse_repo_json(BASELINE_PATH)
}

fn array<'a>(value: &'a Value, key: &str) -> &'a [Value] {
    value
        .get(key)
        .and_then(Value::as_array)
        .map_or_else(|| panic!("{key} must be an array"), Vec::as_slice)
}

fn object<'a>(value: &'a Value, key: &str) -> &'a Map<String, Value> {
    value
        .get(key)
        .and_then(Value::as_object)
        .unwrap_or_else(|| panic!("{key} must be an object"))
}

fn string<'a>(value: &'a Value, key: &str) -> &'a str {
    let text = value
        .get(key)
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("{key} must be a string"));
    assert!(!text.trim().is_empty(), "{key} must be nonempty");
    text
}

fn bool_field(value: &Value, key: &str) -> bool {
    value
        .get(key)
        .and_then(Value::as_bool)
        .unwrap_or_else(|| panic!("{key} must be a bool"))
}

fn strings(value: &Value, key: &str) -> Vec<String> {
    array(value, key)
        .iter()
        .map(|entry| {
            entry
                .as_str()
                .unwrap_or_else(|| panic!("{key} entries must be strings"))
                .to_owned()
        })
        .collect()
}

fn string_set(value: &Value, key: &str) -> BTreeSet<String> {
    strings(value, key).into_iter().collect()
}

fn expected_set(values: &[&str]) -> BTreeSet<String> {
    values.iter().map(|value| (*value).to_owned()).collect()
}

fn keyed_rows<'a>(value: &'a Value, array_key: &str, id_key: &str) -> BTreeMap<String, &'a Value> {
    let mut rows = BTreeMap::new();
    for row in array(value, array_key) {
        let id = string(row, id_key).to_owned();
        assert!(
            rows.insert(id.clone(), row).is_none(),
            "duplicate {id_key} {id}"
        );
    }
    rows
}

fn repo_file_exists(relative: &str) -> bool {
    repo_path(relative).is_file()
}

fn live_bead_ids() -> BTreeSet<String> {
    read_repo_file(BEADS_PATH)
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| {
            let issue: Value =
                serde_json::from_str(line).unwrap_or_else(|error| panic!("parse bead: {error}"));
            string(&issue, "id").to_owned()
        })
        .collect()
}

fn class_row<'a>(policy: &'a Value, class_id: &str) -> &'a Value {
    array(policy, "migration_classes")
        .iter()
        .find(|row| row.get("class_id").and_then(Value::as_str) == Some(class_id))
        .unwrap_or_else(|| panic!("missing migration class {class_id}"))
}

fn binding_row<'a>(policy: &'a Value, capability_id: &str) -> &'a Value {
    array(policy, "capability_bindings")
        .iter()
        .find(|row| row.get("capability_id").and_then(Value::as_str) == Some(capability_id))
        .unwrap_or_else(|| panic!("missing capability binding {capability_id}"))
}

fn registry_row<'a>(registry: &'a Value, capability_id: &str) -> &'a Value {
    array(registry, "capabilities")
        .iter()
        .find(|row| row.get("capability_id").and_then(Value::as_str) == Some(capability_id))
        .unwrap_or_else(|| panic!("missing registry capability {capability_id}"))
}

fn baseline_row<'a>(baseline: &'a Value, capability_id: &str) -> &'a Value {
    array(baseline, "capability_baselines")
        .iter()
        .find(|row| row.get("capability_id").and_then(Value::as_str) == Some(capability_id))
        .unwrap_or_else(|| panic!("missing baseline capability {capability_id}"))
}

fn required_gates_for_capability(policy: &Value, capability_id: &str) -> BTreeSet<String> {
    let binding = binding_row(policy, capability_id);
    let class = class_row(policy, string(binding, "migration_class"));
    let mut gates = string_set(policy, "global_gate_ids");
    gates.extend(string_set(class, "additional_gate_ids"));
    gates
}

fn policy_errors(policy: &Value, registry: &Value, baseline: &Value) -> Vec<String> {
    let mut errors = Vec::new();

    if policy.get("schema_version").and_then(Value::as_u64) != Some(1) {
        errors.push("schema_version must be 1".to_owned());
    }
    if policy.get("artifact_id").and_then(Value::as_str) != Some("dependency-cutover-policy-v1") {
        errors.push("artifact_id drift".to_owned());
    }
    if policy.get("program_id").and_then(Value::as_str) != Some(PROGRAM_ID) {
        errors.push("program_id drift".to_owned());
    }
    if policy.get("bead_id").and_then(Value::as_str) != Some(BEAD_ID) {
        errors.push("bead_id drift".to_owned());
    }

    let expected_verdicts = expected_set(TERMINAL_VERDICTS);
    let verdicts = array(policy, "terminal_verdicts")
        .iter()
        .filter_map(|row| row.get("verdict").and_then(Value::as_str))
        .map(str::to_owned)
        .collect::<BTreeSet<_>>();
    if verdicts != expected_verdicts {
        errors.push("terminal verdict taxonomy drift".to_owned());
    }

    let expected_parity = expected_set(PARITY_RESULTS);
    let parity = array(policy, "parity_results")
        .iter()
        .filter_map(|row| row.get("result").and_then(Value::as_str))
        .map(str::to_owned)
        .collect::<BTreeSet<_>>();
    if parity != expected_parity {
        errors.push("parity taxonomy drift".to_owned());
    }

    let expected_outcomes = expected_set(EVIDENCE_OUTCOMES);
    let outcomes = array(policy, "evidence_outcomes")
        .iter()
        .filter_map(|row| row.get("outcome").and_then(Value::as_str))
        .map(str::to_owned)
        .collect::<BTreeSet<_>>();
    if outcomes != expected_outcomes {
        errors.push("evidence outcome taxonomy drift".to_owned());
    }

    let gate_fields = string_set(policy, "gate_required_fields");
    let gate_rows = keyed_rows(policy, "gate_catalog", "gate_id");
    for (gate_id, row) in &gate_rows {
        let actual_fields = row
            .as_object()
            .map(|map| map.keys().cloned().collect::<BTreeSet<_>>())
            .unwrap_or_default();
        if actual_fields != gate_fields {
            errors.push(format!("{gate_id}: gate field drift"));
        }
        if string_set(row, "advance_outcomes") != BTreeSet::from(["PASS".to_owned()]) {
            errors.push(format!("{gate_id}: only PASS may advance a required gate"));
        }
    }
    if string_set(policy, "global_gate_ids") != expected_set(REQUIRED_GLOBAL_GATES) {
        errors.push("global gate inventory drift".to_owned());
    }
    for gate_id in string_set(policy, "global_gate_ids") {
        if !gate_rows.contains_key(&gate_id) {
            errors.push(format!("missing global gate {gate_id}"));
        }
    }

    let class_fields = string_set(policy, "migration_class_required_fields");
    let class_rows = keyed_rows(policy, "migration_classes", "class_id");
    if class_rows.keys().cloned().collect::<BTreeSet<_>>()
        != expected_set(REQUIRED_MIGRATION_CLASSES)
    {
        errors.push("migration class inventory drift".to_owned());
    }
    for (class_id, row) in &class_rows {
        let actual_fields = row
            .as_object()
            .map(|map| map.keys().cloned().collect::<BTreeSet<_>>())
            .unwrap_or_default();
        if actual_fields != class_fields {
            errors.push(format!("{class_id}: migration class field drift"));
        }
        for gate_id in string_set(row, "additional_gate_ids") {
            if !gate_rows.contains_key(&gate_id) {
                errors.push(format!("{class_id}: unknown additional gate {gate_id}"));
            }
        }
    }

    let binding_fields = string_set(policy, "capability_binding_required_fields");
    let binding_rows = keyed_rows(policy, "capability_bindings", "capability_id");
    let registry_rows = keyed_rows(registry, "capabilities", "capability_id");
    let baseline_rows = keyed_rows(baseline, "capability_baselines", "capability_id");
    if binding_rows.keys().cloned().collect::<BTreeSet<_>>()
        != registry_rows.keys().cloned().collect::<BTreeSet<_>>()
    {
        errors.push("capability binding coverage differs from registry".to_owned());
    }
    if binding_rows.keys().cloned().collect::<BTreeSet<_>>()
        != baseline_rows.keys().cloned().collect::<BTreeSet<_>>()
    {
        errors.push("capability binding coverage differs from baseline".to_owned());
    }
    for (capability_id, row) in &binding_rows {
        let actual_fields = row
            .as_object()
            .map(|map| map.keys().cloned().collect::<BTreeSet<_>>())
            .unwrap_or_default();
        if actual_fields != binding_fields {
            errors.push(format!("{capability_id}: binding field drift"));
        }
        let class_id = string(row, "migration_class");
        if !class_rows.contains_key(class_id) {
            errors.push(format!(
                "{capability_id}: unknown migration class {class_id}"
            ));
        }
        let role = string(row, "binding_role");
        if !BINDING_ROLES.contains(&role) {
            errors.push(format!("{capability_id}: unknown binding role {role}"));
        }
        let Some(registry_row) = registry_rows.get(capability_id) else {
            continue;
        };
        let registry_state = string(registry_row, "cutover_state");
        if string(row, "registry_cutover_state") != registry_state {
            errors.push(format!("{capability_id}: registry cutover state drift"));
        }
        let expected_role = if registry_state == "NOT_A_CUTOVER" {
            "GUARD_ONLY"
        } else {
            "CUTOVER_TARGET"
        };
        if role != expected_role {
            errors.push(format!(
                "{capability_id}: binding role disagrees with registry state"
            ));
        }
        if bool_field(row, "dependency_exit_allowed") {
            errors.push(format!(
                "{capability_id}: current dependency exit must remain disabled"
            ));
        }
    }

    let machine = &policy["cutover_state_machine"];
    let states = array(machine, "states")
        .iter()
        .filter_map(|row| row.get("state").and_then(Value::as_str))
        .map(str::to_owned)
        .collect::<BTreeSet<_>>();
    if states != expected_set(REQUIRED_STATES) {
        errors.push("cutover state inventory drift".to_owned());
    }
    for transition in array(machine, "transitions") {
        let from = string(transition, "from");
        let to = string(transition, "to");
        if !states.contains(from) || !states.contains(to) {
            errors.push(format!("transition references unknown state {from}->{to}"));
        }
        for gate_id in string_set(transition, "required_gate_ids") {
            if !gate_rows.contains_key(&gate_id) {
                errors.push(format!(
                    "transition {from}->{to} references unknown gate {gate_id}"
                ));
            }
        }
    }
    let transition_pairs = array(machine, "transitions")
        .iter()
        .map(|row| format!("{}->{}", string(row, "from"), string(row, "to")))
        .collect::<BTreeSet<_>>();
    for forbidden in string_set(machine, "forbidden_transitions") {
        if transition_pairs.contains(&forbidden) {
            errors.push(format!("forbidden transition is enabled: {forbidden}"));
        }
    }

    let receipt_fields = string_set(policy, "decision_receipt_required_fields");
    if receipt_fields != expected_set(DECISION_RECEIPT_FIELDS) {
        errors.push("decision receipt field inventory drift".to_owned());
    }

    errors
}

fn valid_replace_receipt(
    policy: &Value,
    registry: &Value,
    baseline: &Value,
    capability_id: &str,
) -> Value {
    let binding = binding_row(policy, capability_id);
    let class_id = string(binding, "migration_class");
    let base = baseline_row(baseline, capability_id);
    let parity_results = strings(base, "parity_modes")
        .into_iter()
        .map(|mode| {
            json!({
                "capability_id": capability_id,
                "parity_mode": mode,
                "result": "SAME",
                "evidence_ref": format!("fixture://parity/{capability_id}")
            })
        })
        .collect::<Vec<_>>();
    let case_results = array(baseline, "case_classes")
        .iter()
        .map(|case| {
            json!({
                "capability_id": capability_id,
                "case_class": case.as_str().expect("case string"),
                "outcome": "PASS",
                "evidence_ref": format!("fixture://case/{capability_id}")
            })
        })
        .collect::<Vec<_>>();
    let gate_results = required_gates_for_capability(policy, capability_id)
        .into_iter()
        .map(|gate_id| {
            json!({
                "gate_id": gate_id,
                "outcome": "PASS",
                "evidence_ref": format!("fixture://gate/{capability_id}")
            })
        })
        .collect::<Vec<_>>();
    let class = class_row(policy, class_id);
    let migration_required =
        !string_set(class, "additional_gate_ids").is_disjoint(&BTreeSet::from([
            "GATE-MIGRATION".to_owned(),
            "GATE-CYCLE-SAFE-RELOCATION".to_owned(),
        ]));

    let registry_capability = registry_row(registry, capability_id);
    json!({
        "candidate_id": "fixture-complete-replacement",
        "affected_capability_ids": [capability_id],
        "requested_verdict": "REPLACE",
        "decision_reason": "Hypothetical structurally complete same-or-better fixture for contract testing only.",
        "resume_conditions": [],
        "blocking_owners": [],
        "source_revision": "0123456789abcdef0123456789abcdef01234567",
        "evidence_as_of_utc": "2026-07-24T00:00:00Z",
        "parity_results": parity_results,
        "case_results": case_results,
        "gate_results": gate_results,
        "feature_loss": false,
        "api_narrowing": false,
        "format_rejection": false,
        "unresolved_regressions": [],
        "downstream_receipts": [{
            "consumer_id": "fixture-public-consumer",
            "status": "PASS",
            "scenario_ids": registry_capability["scenario_ids"].clone(),
            "evidence_ref": "fixture://downstream/public"
        }],
        "migration_plan": {
            "status": "PASS",
            "required": migration_required,
            "old_inputs_preserved": true,
            "deletion_authorized": false,
            "coexistence": {
                "mode": string(class, "coexistence_mode"),
                "incumbent_remains_primary": true,
                "input_selection": "deterministic bounded fixture and shadow selection",
                "output_comparison": "structured exact-mode and semantic-mode comparison",
                "side_effect_isolation": "candidate side effects are disabled or isolated",
                "resource_budget": "bounded by the candidate acceptance envelope",
                "cancellation_cleanup": "zero residual tasks, handles, obligations, and partial writes",
                "observation_window": "candidate-specific owner-approved window",
                "promotion_criteria": "all required gates PASS with no unknown or regression",
                "rollback_trigger": "any correctness, security, compatibility, resource, or UX threshold breach"
            }
        },
        "rollback_plan": {
            "status": "PASS",
            "pre_cutover_revision": "fedcba9876543210fedcba9876543210fedcba98",
            "pre_cutover_lockfile_digest": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "trigger_thresholds": ["any correctness or safety failure", "any unsupported required capability"],
            "artifact_compatibility": "candidate-era artifacts remain readable or have a proven lossless reverse migrator",
            "incumbent_restore_steps": ["restore exact revision and lockfile", "re-enable incumbent path", "replay focused evidence"],
            "state_reconciliation": "drain candidate work and reconcile versioned state without loss",
            "cleanup_assertions": ["zero residual tasks", "zero residual handles", "no partial write", "no retained secret"],
            "verification_command": "RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_TARGET_DIR=/tmp/fixture cargo test -p asupersync --test dependency_cutover_policy_contract",
            "operator_owner": BEAD_ID,
            "maximum_recovery_time": "candidate-specific measured bound",
            "rehearsal_receipt": "fixture://rollback/rehearsal"
        },
        "platform_matrix": {
            "required": class_id == "PLATFORM_BOUNDARY" || class_id == "CONCURRENCY_PERFORMANCE",
            "status": "PASS",
            "required_cells": ["fixture-supported-cell"],
            "unsupported_required_cells": [],
            "evidence_ref": "fixture://platform/matrix"
        },
        "service_matrix": {
            "required": class_id == "SERVICE_INTEROP" || class_id == "DOWNSTREAM_RELOCATION",
            "status": "PASS",
            "required_versions": ["fixture-pinned-service"],
            "missing_versions": [],
            "evidence_ref": "fixture://service/matrix"
        },
        "security_review": {
            "required": class_id == "SECURITY_SENSITIVE",
            "status": "PASS",
            "independent_review": true,
            "fail_closed": true,
            "redaction_verified": true,
            "evidence_ref": "fixture://security/review"
        },
        "performance_review": {
            "required": class_id == "CONCURRENCY_PERFORMANCE",
            "status": "PASS",
            "no_regression": true,
            "tracked_axes_complete": true,
            "evidence_ref": "fixture://performance/review"
        },
        "oracle_disposition": {
            "status": "PASS",
            "graph_safe": true,
            "cycle_safe": true,
            "expiry_or_retirement_recorded": true,
            "evidence_ref": "fixture://oracle/disposition"
        },
        "documentation_receipt": {
            "status": "PASS",
            "paths": ["docs/dependency_cutover_policy.md"],
            "help_errors_examples_install_migration_recovery_rollback": true,
            "evidence_ref": "fixture://docs/review"
        },
        "owner_signoffs": [{
            "owner": BEAD_ID,
            "scope": "fixture-only policy contract",
            "status": "PASS",
            "evidence_ref": "fixture://owner/signoff"
        }],
        "state_transition": {
            "from": "CUTOVER_CANDIDATE",
            "to": "REPLACEMENT_PRIMARY"
        },
        "production_switch_requested": true,
        "campaign_close_requested": true,
        "incumbent_action": "EXIT_AFTER_OBSERVATION",
        "no_claim_boundaries": [
            "does_not_authorize_a_real_cutover",
            "does_not_prove_broad_workspace_health",
            "does_not_prove_release_readiness"
        ]
    })
}

fn field_is_false(receipt: &Value, key: &str) -> bool {
    receipt.get(key).and_then(Value::as_bool) == Some(false)
}

fn decision_errors(
    policy: &Value,
    registry: &Value,
    baseline: &Value,
    receipt: &Value,
) -> Vec<String> {
    let mut errors = Vec::new();
    let expected_fields = string_set(policy, "decision_receipt_required_fields");
    let actual_fields = receipt
        .as_object()
        .map(|map| map.keys().cloned().collect::<BTreeSet<_>>())
        .unwrap_or_default();
    if actual_fields != expected_fields {
        errors.push("decision receipt field drift".to_owned());
    }

    let candidate_id = receipt
        .get("candidate_id")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if candidate_id.trim().is_empty() {
        errors.push("candidate_id must be nonempty".to_owned());
    }
    let reason = receipt
        .get("decision_reason")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if reason.trim().is_empty() {
        errors.push("decision_reason must be nonempty".to_owned());
    }
    let source_revision = receipt
        .get("source_revision")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if source_revision.len() != 40 || !source_revision.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        errors.push("source_revision must be a full hexadecimal commit".to_owned());
    }
    let evidence_time = receipt
        .get("evidence_as_of_utc")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if !evidence_time.ends_with('Z') || !evidence_time.contains('T') {
        errors.push("evidence_as_of_utc must be an ISO-8601 UTC timestamp".to_owned());
    }

    let capability_ids = strings(receipt, "affected_capability_ids");
    if capability_ids.is_empty() {
        errors.push("at least one affected capability is required".to_owned());
    }
    if capability_ids.iter().collect::<BTreeSet<_>>().len() != capability_ids.len() {
        errors.push("affected capability IDs must be unique".to_owned());
    }
    let bindings = keyed_rows(policy, "capability_bindings", "capability_id");
    for capability_id in &capability_ids {
        match bindings.get(capability_id) {
            Some(binding) if string(binding, "binding_role") == "CUTOVER_TARGET" => {}
            Some(_) => errors.push(format!(
                "{capability_id}: guard-only capability cannot be cut over"
            )),
            None => errors.push(format!("{capability_id}: unmapped capability")),
        }
    }

    let verdict = receipt
        .get("requested_verdict")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if !TERMINAL_VERDICTS.contains(&verdict) {
        errors.push("unknown requested verdict".to_owned());
        return errors;
    }

    let production_switch = receipt
        .get("production_switch_requested")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let campaign_close = receipt
        .get("campaign_close_requested")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let incumbent_action = receipt
        .get("incumbent_action")
        .and_then(Value::as_str)
        .unwrap_or_default();

    match verdict {
        "KEEP" => {
            if production_switch || !campaign_close || incumbent_action != "KEEP" {
                errors.push(
                    "KEEP must close without a production switch and keep incumbent".to_owned(),
                );
            }
        }
        "DEFER" => {
            if production_switch || !campaign_close || incumbent_action != "KEEP" {
                errors.push(
                    "DEFER must close without a production switch and keep incumbent".to_owned(),
                );
            }
            if array(receipt, "resume_conditions").is_empty() {
                errors.push("DEFER requires resume conditions".to_owned());
            }
        }
        "BLOCKED" => {
            if production_switch || campaign_close || incumbent_action != "KEEP" {
                errors.push("BLOCKED must remain open without a production switch".to_owned());
            }
            if array(receipt, "blocking_owners").is_empty() {
                errors.push("BLOCKED requires blocking owners".to_owned());
            }
        }
        "REPLACE" => {
            if !production_switch || !campaign_close || incumbent_action != "EXIT_AFTER_OBSERVATION"
            {
                errors.push(
                    "REPLACE requires a serialized production switch and delayed incumbent exit"
                        .to_owned(),
                );
            }
            if !field_is_false(receipt, "feature_loss") {
                errors.push("REPLACE cannot lose a feature".to_owned());
            }
            if !field_is_false(receipt, "api_narrowing") {
                errors.push("REPLACE cannot narrow a public or generic API".to_owned());
            }
            if !field_is_false(receipt, "format_rejection") {
                errors.push("REPLACE cannot reject a currently accepted format".to_owned());
            }
            if !array(receipt, "unresolved_regressions").is_empty() {
                errors.push("REPLACE cannot carry unresolved regressions".to_owned());
            }
            if !array(receipt, "resume_conditions").is_empty()
                || !array(receipt, "blocking_owners").is_empty()
            {
                errors.push("REPLACE cannot carry defer or blocker fields".to_owned());
            }

            let parity_rows = array(receipt, "parity_results");
            for capability_id in &capability_ids {
                if !bindings.contains_key(capability_id) {
                    continue;
                }
                let expected_modes =
                    string_set(baseline_row(baseline, capability_id), "parity_modes");
                let mut observed_modes = BTreeSet::new();
                for row in parity_rows.iter().filter(|row| {
                    row.get("capability_id").and_then(Value::as_str) == Some(capability_id.as_str())
                }) {
                    let mode = string(row, "parity_mode").to_owned();
                    if !observed_modes.insert(mode.clone()) {
                        errors.push(format!("{capability_id}: duplicate parity mode {mode}"));
                    }
                    match string(row, "result") {
                        "SAME" | "BETTER" => {}
                        other => errors.push(format!(
                            "{capability_id}: parity result {other} cannot advance REPLACE"
                        )),
                    }
                    if row
                        .get("evidence_ref")
                        .and_then(Value::as_str)
                        .is_none_or(str::is_empty)
                    {
                        errors.push(format!("{capability_id}: parity evidence_ref is required"));
                    }
                }
                if observed_modes != expected_modes {
                    errors.push(format!(
                        "{capability_id}: parity-mode coverage is incomplete"
                    ));
                }
            }

            let case_rows = array(receipt, "case_results");
            for capability_id in &capability_ids {
                if !bindings.contains_key(capability_id) {
                    continue;
                }
                let observed_cases = case_rows
                    .iter()
                    .filter(|row| {
                        row.get("capability_id").and_then(Value::as_str)
                            == Some(capability_id.as_str())
                    })
                    .map(|row| {
                        if string(row, "outcome") != "PASS" {
                            errors.push(format!(
                                "{capability_id}: every required case must PASS for REPLACE"
                            ));
                        }
                        string(row, "case_class").to_owned()
                    })
                    .collect::<BTreeSet<_>>();
                if observed_cases != expected_set(REQUIRED_CASE_CLASSES) {
                    errors.push(format!(
                        "{capability_id}: case-class coverage is incomplete"
                    ));
                }
            }

            let observed_gates = array(receipt, "gate_results")
                .iter()
                .map(|row| {
                    if string(row, "outcome") != "PASS" {
                        errors.push(format!(
                            "{}: required gate outcome is not PASS",
                            string(row, "gate_id")
                        ));
                    }
                    string(row, "gate_id").to_owned()
                })
                .collect::<BTreeSet<_>>();
            let mut expected_gates = BTreeSet::new();
            for capability_id in &capability_ids {
                if bindings.contains_key(capability_id) {
                    expected_gates.extend(required_gates_for_capability(policy, capability_id));
                }
            }
            if observed_gates != expected_gates {
                errors.push(
                    "required gate coverage is incomplete or contains unknown gates".to_owned(),
                );
            }

            if array(receipt, "downstream_receipts").is_empty()
                || array(receipt, "downstream_receipts")
                    .iter()
                    .any(|row| row.get("status").and_then(Value::as_str) != Some("PASS"))
            {
                errors.push("REPLACE requires passing downstream receipts".to_owned());
            }

            let migration_value = &receipt["migration_plan"];
            let migration = object(receipt, "migration_plan");
            if migration.get("status").and_then(Value::as_str) != Some("PASS")
                || migration
                    .get("old_inputs_preserved")
                    .and_then(Value::as_bool)
                    != Some(true)
                || migration
                    .get("deletion_authorized")
                    .and_then(Value::as_bool)
                    != Some(false)
            {
                errors.push(
                    "migration must pass, preserve old inputs, and forbid deletion".to_owned(),
                );
            }
            let coexistence = object(migration_value, "coexistence");
            let coexistence_fields = coexistence.keys().cloned().collect::<BTreeSet<_>>();
            if coexistence_fields != string_set(policy, "coexistence_required_fields") {
                errors.push("coexistence receipt field coverage is incomplete".to_owned());
            }
            let requires_migration = capability_ids.iter().any(|capability_id| {
                if !bindings.contains_key(capability_id) {
                    return false;
                }
                required_gates_for_capability(policy, capability_id).contains("GATE-MIGRATION")
            });
            if requires_migration
                && migration.get("required").and_then(Value::as_bool) != Some(true)
            {
                errors.push("stateful or durable class requires a migration plan".to_owned());
            }

            let rollback = object(receipt, "rollback_plan");
            if rollback.keys().cloned().collect::<BTreeSet<_>>()
                != string_set(policy, "rollback_required_fields")
                || rollback.get("status").and_then(Value::as_str) != Some("PASS")
            {
                errors.push("rollback receipt is incomplete or not PASS".to_owned());
            }

            let class_ids = capability_ids
                .iter()
                .filter_map(|capability_id| bindings.get(capability_id))
                .map(|binding| string(binding, "migration_class"))
                .collect::<BTreeSet<_>>();
            let platform = object(receipt, "platform_matrix");
            if (class_ids.contains("PLATFORM_BOUNDARY")
                || class_ids.contains("CONCURRENCY_PERFORMANCE"))
                && (platform.get("required").and_then(Value::as_bool) != Some(true)
                    || platform.get("status").and_then(Value::as_str) != Some("PASS")
                    || !array(&receipt["platform_matrix"], "unsupported_required_cells").is_empty())
            {
                errors.push("required platform matrix is incomplete or unsupported".to_owned());
            }
            let service = object(receipt, "service_matrix");
            if (class_ids.contains("SERVICE_INTEROP")
                || class_ids.contains("DOWNSTREAM_RELOCATION"))
                && (service.get("required").and_then(Value::as_bool) != Some(true)
                    || service.get("status").and_then(Value::as_str) != Some("PASS")
                    || !array(&receipt["service_matrix"], "missing_versions").is_empty())
            {
                errors.push("required real-service matrix is incomplete".to_owned());
            }
            let security = object(receipt, "security_review");
            if class_ids.contains("SECURITY_SENSITIVE")
                && (security.get("required").and_then(Value::as_bool) != Some(true)
                    || security.get("status").and_then(Value::as_str) != Some("PASS")
                    || security.get("independent_review").and_then(Value::as_bool) != Some(true)
                    || security.get("fail_closed").and_then(Value::as_bool) != Some(true)
                    || security.get("redaction_verified").and_then(Value::as_bool) != Some(true))
            {
                errors.push("required security review is incomplete".to_owned());
            }
            let performance = object(receipt, "performance_review");
            if class_ids.contains("CONCURRENCY_PERFORMANCE")
                && (performance.get("required").and_then(Value::as_bool) != Some(true)
                    || performance.get("status").and_then(Value::as_str) != Some("PASS")
                    || performance.get("no_regression").and_then(Value::as_bool) != Some(true)
                    || performance
                        .get("tracked_axes_complete")
                        .and_then(Value::as_bool)
                        != Some(true))
            {
                errors.push("required performance review is incomplete or regressed".to_owned());
            }
            let oracle = object(receipt, "oracle_disposition");
            if oracle.get("status").and_then(Value::as_str) != Some("PASS")
                || oracle.get("graph_safe").and_then(Value::as_bool) != Some(true)
                || oracle.get("cycle_safe").and_then(Value::as_bool) != Some(true)
                || oracle
                    .get("expiry_or_retirement_recorded")
                    .and_then(Value::as_bool)
                    != Some(true)
            {
                errors.push(
                    "oracle disposition must pass graph, cycle, and retirement gates".to_owned(),
                );
            }
            let documentation = object(receipt, "documentation_receipt");
            if documentation.get("status").and_then(Value::as_str) != Some("PASS")
                || array(&receipt["documentation_receipt"], "paths").is_empty()
                || documentation
                    .get("help_errors_examples_install_migration_recovery_rollback")
                    .and_then(Value::as_bool)
                    != Some(true)
            {
                errors.push("documentation and operator UX receipt is incomplete".to_owned());
            }
            if array(receipt, "owner_signoffs").is_empty()
                || array(receipt, "owner_signoffs")
                    .iter()
                    .any(|row| row.get("status").and_then(Value::as_str) != Some("PASS"))
            {
                errors.push("required owner signoffs are missing".to_owned());
            }
            let transition = object(receipt, "state_transition");
            if transition.get("from").and_then(Value::as_str) != Some("CUTOVER_CANDIDATE")
                || transition.get("to").and_then(Value::as_str) != Some("REPLACEMENT_PRIMARY")
            {
                errors.push("REPLACE must use the serialized cutover transition".to_owned());
            }
        }
        _ => unreachable!(),
    }

    if array(receipt, "no_claim_boundaries").len() < 3 {
        errors.push("decision receipt requires at least three no-claim boundaries".to_owned());
    }
    let registry_rows = keyed_rows(registry, "capabilities", "capability_id");
    if capability_ids.iter().any(|capability_id| {
        registry_rows
            .get(capability_id)
            .is_some_and(|row| row["replacement_bead_ids"].as_array().is_none())
    }) {
        errors.push("affected capability lacks replacement ownership".to_owned());
    }

    errors
}

fn non_replace_receipt(verdict: &str) -> Value {
    let (close, resume, blockers) = match verdict {
        "KEEP" => (true, json!([]), json!([])),
        "DEFER" => (
            true,
            json!(["obtain the required platform or external-service evidence"]),
            json!(["asupersync-dep-p1-foundations-upksjk.6.5"]),
        ),
        "BLOCKED" => (
            false,
            json!(["obtain an explicit product-owner decision"]),
            json!(["asupersync-dep-p1-foundations-upksjk.5.4"]),
        ),
        other => panic!("unsupported fixture verdict {other}"),
    };
    json!({
        "candidate_id": "fixture-non-replace",
        "affected_capability_ids": ["CAP-HEX-CODEC"],
        "requested_verdict": verdict,
        "decision_reason": format!("Fixture {verdict} reason with explicit incumbent retention."),
        "resume_conditions": resume,
        "blocking_owners": blockers,
        "source_revision": "0123456789abcdef0123456789abcdef01234567",
        "evidence_as_of_utc": "2026-07-24T00:00:00Z",
        "parity_results": [],
        "case_results": [],
        "gate_results": [],
        "feature_loss": false,
        "api_narrowing": false,
        "format_rejection": false,
        "unresolved_regressions": [],
        "downstream_receipts": [],
        "migration_plan": {},
        "rollback_plan": {},
        "platform_matrix": {},
        "service_matrix": {},
        "security_review": {},
        "performance_review": {},
        "oracle_disposition": {},
        "documentation_receipt": {},
        "owner_signoffs": [],
        "state_transition": {"from": "INCUMBENT_PRIMARY", "to": "INCUMBENT_PRIMARY"},
        "production_switch_requested": false,
        "campaign_close_requested": close,
        "incumbent_action": "KEEP",
        "no_claim_boundaries": [
            "does_not_authorize_cutover",
            "does_not_prove_replacement_parity",
            "does_not_remove_the_incumbent"
        ]
    })
}

#[test]
fn canonical_policy_is_complete_and_fail_closed() {
    let errors = policy_errors(&policy(), &registry(), &baseline());
    assert!(errors.is_empty(), "policy errors:\n{}", errors.join("\n"));
}

#[test]
fn source_contracts_resolve_to_exact_artifact_ids() {
    let policy = policy();
    let expected = BTreeMap::from([
        (TAXONOMY_PATH, "dependency-safety-taxonomy-v1"),
        (LEDGER_PATH, "dependency-marginal-ledger-v1"),
        (ORACLE_PATH, "dependency-oracle-policy-v1"),
        (REGISTRY_PATH, "dependency-capability-registry-v1"),
        (BASELINE_PATH, "dependency-capability-baseline-v1"),
    ]);
    let observed = array(&policy, "source_contracts")
        .iter()
        .map(|row| (string(row, "path"), string(row, "artifact_id")))
        .collect::<BTreeMap<_, _>>();
    assert_eq!(observed, expected);
    for (path, artifact_id) in expected {
        assert!(repo_file_exists(path), "source contract must exist: {path}");
        assert_eq!(
            parse_repo_json(path)
                .get("artifact_id")
                .and_then(Value::as_str),
            Some(artifact_id),
            "{path}: artifact identity drift"
        );
    }
}

#[test]
fn terminal_verdicts_encode_the_incumbent_and_closeout_rules() {
    let policy = policy();
    let verdicts = keyed_rows(&policy, "terminal_verdicts", "verdict");
    assert!(bool_field(verdicts["REPLACE"], "campaign_may_close"));
    assert!(bool_field(verdicts["REPLACE"], "production_switch_allowed"));
    assert!(!bool_field(verdicts["REPLACE"], "incumbent_must_remain"));
    for verdict in ["KEEP", "DEFER"] {
        assert!(bool_field(verdicts[verdict], "campaign_may_close"));
        assert!(!bool_field(verdicts[verdict], "production_switch_allowed"));
        assert!(bool_field(verdicts[verdict], "incumbent_must_remain"));
    }
    assert!(!bool_field(verdicts["BLOCKED"], "campaign_may_close"));
    assert!(!bool_field(
        verdicts["BLOCKED"],
        "production_switch_allowed"
    ));
    assert!(bool_field(verdicts["BLOCKED"], "incumbent_must_remain"));
}

#[test]
fn only_same_and_better_parity_results_advance() {
    let policy = policy();
    for row in array(&policy, "parity_results") {
        let result = string(row, "result");
        assert_eq!(
            bool_field(row, "advances_cutover"),
            matches!(result, "SAME" | "BETTER"),
            "{result}: parity advance rule"
        );
    }
}

#[test]
fn only_pass_evidence_is_green() {
    let policy = policy();
    for row in array(&policy, "evidence_outcomes") {
        assert_eq!(
            bool_field(row, "green"),
            string(row, "outcome") == "PASS",
            "{}: evidence green rule",
            string(row, "outcome")
        );
    }
}

#[test]
fn every_required_gate_is_fail_closed() {
    let policy = policy();
    for row in array(&policy, "gate_catalog") {
        assert_eq!(
            string_set(row, "advance_outcomes"),
            BTreeSet::from(["PASS".to_owned()]),
            "{}: required gates only advance on PASS",
            string(row, "gate_id")
        );
        assert!(
            !string(row, "failure_behavior").trim().is_empty(),
            "{}: failure behavior",
            string(row, "gate_id")
        );
    }
}

#[test]
fn migration_classes_cover_every_risk_family() {
    let policy = policy();
    let classes = keyed_rows(&policy, "migration_classes", "class_id");
    assert_eq!(
        classes.keys().cloned().collect::<BTreeSet<_>>(),
        expected_set(REQUIRED_MIGRATION_CLASSES)
    );
    for (class_id, row) in classes {
        for key in [
            "description",
            "coexistence_mode",
            "write_policy",
            "rollback_mode",
            "deletion_policy",
        ] {
            assert!(
                string(row, key).len() >= 24,
                "{class_id}: {key} must be substantive"
            );
        }
    }
}

#[test]
fn state_machine_has_no_direct_cutover_or_dependency_exit_bypass() {
    let policy = policy();
    let machine = &policy["cutover_state_machine"];
    let transitions = array(machine, "transitions")
        .iter()
        .map(|row| (string(row, "from"), string(row, "to")))
        .collect::<BTreeSet<_>>();
    for forbidden in [
        ("INCUMBENT_PRIMARY", "CUTOVER_CANDIDATE"),
        ("INCUMBENT_PRIMARY", "REPLACEMENT_PRIMARY"),
        ("PROTOTYPE_ISOLATED", "REPLACEMENT_PRIMARY"),
        ("SHADOW", "REPLACEMENT_PRIMARY"),
        ("COEXISTENCE", "REPLACEMENT_PRIMARY"),
        ("REPLACEMENT_PRIMARY", "DEPENDENCY_EXITED"),
        ("ROLLBACK_ACTIVE", "DEPENDENCY_EXITED"),
    ] {
        assert!(!transitions.contains(&forbidden), "forbidden {forbidden:?}");
    }
}

#[test]
fn replacement_primary_is_reachable_only_through_full_evidence_path() {
    let policy = policy();
    let machine = &policy["cutover_state_machine"];
    let transitions = array(machine, "transitions");
    let mut predecessors: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    for transition in transitions {
        predecessors
            .entry(string(transition, "to"))
            .or_default()
            .push(string(transition, "from"));
    }
    assert_eq!(
        predecessors["REPLACEMENT_PRIMARY"],
        vec!["CUTOVER_CANDIDATE"]
    );

    let mut queue = VecDeque::from(["INCUMBENT_PRIMARY"]);
    let mut reachable = BTreeSet::new();
    while let Some(state) = queue.pop_front() {
        if !reachable.insert(state) {
            continue;
        }
        for transition in transitions
            .iter()
            .filter(|row| string(row, "from") == state)
        {
            queue.push_back(string(transition, "to"));
        }
    }
    for state in REQUIRED_STATES {
        assert!(
            reachable.contains(state),
            "state must be reachable: {state}"
        );
    }
}

#[test]
fn production_switches_exist_only_at_cutover_and_rollback_completion() {
    let policy = policy();
    let machine = &policy["cutover_state_machine"];
    let switching = array(machine, "transitions")
        .iter()
        .filter(|row| bool_field(row, "production_switch"))
        .map(|row| format!("{}->{}", string(row, "from"), string(row, "to")))
        .collect::<BTreeSet<_>>();
    assert_eq!(
        switching,
        BTreeSet::from([
            "CUTOVER_CANDIDATE->REPLACEMENT_PRIMARY".to_owned(),
            "ROLLBACK_ACTIVE->INCUMBENT_RESTORED".to_owned()
        ])
    );
}

#[test]
fn dependency_exit_remains_rollback_reachable() {
    let policy = policy();
    let machine = &policy["cutover_state_machine"];
    let transitions = array(machine, "transitions");
    let exited_rollback = transitions.iter().find(|row| {
        string(row, "from") == "DEPENDENCY_EXITED" && string(row, "to") == "ROLLBACK_ACTIVE"
    });
    let exited_rollback = exited_rollback
        .expect("a post-exit defect must be able to enter the mandatory rollback path");
    assert!(
        array(exited_rollback, "required_gate_ids").is_empty(),
        "rollback activation must not wait for an evidence gate after a trigger fires"
    );
    assert!(
        !bool_field(exited_rollback, "production_switch"),
        "rollback activation drains/reconciles before incumbent restoration"
    );

    let restoration = transitions.iter().find(|row| {
        string(row, "from") == "ROLLBACK_ACTIVE" && string(row, "to") == "INCUMBENT_RESTORED"
    });
    let restoration =
        restoration.expect("rollback must have a verified incumbent-restoration path");
    assert_eq!(
        array(restoration, "required_gate_ids")
            .iter()
            .map(|gate| gate.as_str().expect("gate IDs must be strings"))
            .collect::<BTreeSet<_>>(),
        BTreeSet::from(["GATE-E2E", "GATE-ROLLBACK"])
    );
    assert!(bool_field(restoration, "production_switch"));
}

#[test]
fn capability_bindings_exactly_cover_registry_and_baseline() {
    let policy = policy();
    let registry = registry();
    let baseline = baseline();
    let policy_ids = keyed_rows(&policy, "capability_bindings", "capability_id")
        .keys()
        .cloned()
        .collect::<BTreeSet<_>>();
    assert_eq!(
        policy_ids,
        keyed_rows(&registry, "capabilities", "capability_id")
            .keys()
            .cloned()
            .collect()
    );
    assert_eq!(
        policy_ids,
        keyed_rows(&baseline, "capability_baselines", "capability_id")
            .keys()
            .cloned()
            .collect()
    );
    assert_eq!(policy_ids.len(), 50);
}

#[test]
fn binding_roles_and_registry_states_are_aligned() {
    let policy = policy();
    let registry = registry();
    for binding in array(&policy, "capability_bindings") {
        let capability_id = string(binding, "capability_id");
        let state = string(registry_row(&registry, capability_id), "cutover_state");
        assert_eq!(string(binding, "registry_cutover_state"), state);
        assert_eq!(
            string(binding, "binding_role"),
            if state == "NOT_A_CUTOVER" {
                "GUARD_ONLY"
            } else {
                "CUTOVER_TARGET"
            }
        );
    }
}

#[test]
fn every_current_dependency_exit_is_disabled() {
    for binding in array(&policy(), "capability_bindings") {
        assert!(
            !bool_field(binding, "dependency_exit_allowed"),
            "{} must remain fail closed",
            string(binding, "capability_id")
        );
    }
}

#[test]
fn every_binding_inherits_parity_cases_scenarios_and_live_owners() {
    let policy = policy();
    let registry = registry();
    let baseline = baseline();
    let live_ids = live_bead_ids();
    assert_eq!(
        string_set(&baseline, "case_classes"),
        expected_set(REQUIRED_CASE_CLASSES)
    );
    for binding in array(&policy, "capability_bindings") {
        let capability_id = string(binding, "capability_id");
        let registry_row = registry_row(&registry, capability_id);
        let baseline_row = baseline_row(&baseline, capability_id);
        assert!(!array(baseline_row, "parity_modes").is_empty());
        assert!(!array(registry_row, "scenario_ids").is_empty());
        assert_eq!(
            string_set(registry_row, "scenario_ids"),
            string_set(baseline_row, "scenario_ids")
        );
        for owner_key in ["unit_test_owner", "e2e_owner"] {
            let owner = string(registry_row, owner_key);
            assert!(
                live_ids.contains(owner),
                "{capability_id}: {owner_key} {owner} must exist"
            );
        }
        for replacement in array(registry_row, "replacement_bead_ids") {
            let replacement = replacement.as_str().expect("replacement bead string");
            assert!(
                live_ids.contains(replacement),
                "{capability_id}: replacement bead {replacement} must exist"
            );
        }
    }
}

#[test]
fn generic_public_surfaces_cannot_narrow_to_finite_in_repo_types() {
    let policy = policy();
    let special = keyed_rows(&policy, "special_case_contracts", "case_id");
    let row = special["GENERIC-SERDE-PROST-REGEX"];
    assert_eq!(
        string_set(row, "capability_ids"),
        BTreeSet::from([
            "CAP-PROTOBUF-GENERIC".to_owned(),
            "CAP-REGEX-PRIVACY".to_owned(),
            "CAP-SERDE-GENERIC".to_owned()
        ])
    );
    assert!(string(row, "rule").contains("cannot be replaced by a finite"));
}

#[test]
fn config_migration_preserves_originals_and_requires_deletion_permission() {
    let policy = policy();
    let row = keyed_rows(&policy, "special_case_contracts", "case_id")["CONFIG-DATA-PRESERVATION"];
    let rule = string(row, "rule");
    for required in [
        "Dual-read",
        "comments",
        "anchors",
        "scalar",
        "original files",
        "explicit written permission",
    ] {
        assert!(rule.contains(required), "config rule missing {required}");
    }
}

#[test]
fn frankensqlite_policy_is_cycle_safe_and_user_path_preserving() {
    let policy = policy();
    let binding = binding_row(&policy, "CAP-SQLITE");
    assert_eq!(string(binding, "migration_class"), "DOWNSTREAM_RELOCATION");
    let rule = string(
        keyed_rows(&policy, "special_case_contracts", "case_id")["FRANKENSQLITE-CYCLE"],
        "rule",
    );
    for required in [
        "cannot enter the asupersync workspace graph",
        "neutral consumer or downstream harness",
        "combined graph",
        "official user path",
        "rollback parity",
    ] {
        assert!(rule.contains(required), "SQLite rule missing {required}");
    }
}

#[test]
fn kafka_policy_preserves_the_complete_feature() {
    let policy = policy();
    let rule = string(
        keyed_rows(&policy, "special_case_contracts", "case_id")["KAFKA-CAPABILITY"],
        "rule",
    );
    assert!(rule.contains("No-known-consumer evidence cannot remove Kafka functionality"));
    for required in [
        "protocol",
        "broker",
        "security",
        "lifecycle",
        "performance",
        "downstream",
        "rollback",
    ] {
        assert!(rule.contains(required), "Kafka rule missing {required}");
    }
}

#[test]
fn otlp_policy_preserves_metrics_traces_logs_and_external_ecosystem() {
    let policy = policy();
    let rule = string(
        keyed_rows(&policy, "special_case_contracts", "case_id")["OTLP-ECOSYSTEM"],
        "rule",
    );
    for required in [
        "metrics",
        "traces",
        "logs",
        "external SDK",
        "collector",
        "bounded Cx",
        "no-Tokio",
    ] {
        assert!(rule.contains(required), "OTLP rule missing {required}");
    }
}

#[test]
fn brotli_remains_a_required_interoperability_capability() {
    let policy = policy();
    let rule = string(
        keyed_rows(&policy, "special_case_contracts", "case_id")["BROTLI-INTEROPERABILITY"],
        "rule",
    );
    assert!(rule.contains("current HTTP and ATP manifest capability"));
    assert!(rule.contains("cannot remove it"));
}

#[test]
fn x509_policy_is_delegate_first_and_security_complete() {
    let policy = policy();
    let rule = string(
        keyed_rows(&policy, "special_case_contracts", "case_id")["X509-DELEGATE-FIRST"],
        "rule",
    );
    for required in [
        "rustls/webpki",
        "canonical DER",
        "full consumption",
        "KU/EKU",
        "BasicConstraints",
        "SAN",
        "SPKI",
        "critical extension",
        "handshake",
    ] {
        assert!(rule.contains(required), "X.509 rule missing {required}");
    }
}

#[test]
fn platform_policy_forbids_controller_host_substitution() {
    let policy = policy();
    let rule = string(
        keyed_rows(&policy, "special_case_contracts", "case_id")["PLATFORM-NON-SUBSTITUTION"],
        "rule",
    );
    for required in [
        "Linux", "macOS", "Windows", "BSD", "browsers", "kqueue", "IOCP",
    ] {
        assert!(rule.contains(required), "platform rule missing {required}");
    }
}

#[test]
fn performance_no_win_maps_to_keep_without_axis_deletion() {
    let policy = policy();
    let rule = string(
        keyed_rows(&policy, "special_case_contracts", "case_id")["PERFORMANCE-NO-WIN"],
        "rule",
    );
    for required in [
        "throughput",
        "tail",
        "fairness",
        "cancellation",
        "allocation",
        "RSS",
        "cache",
        "compile",
        "size",
        "core",
        "CPU-family",
        "determinism",
        "KEEP",
    ] {
        assert!(
            rule.contains(required),
            "performance rule missing {required}"
        );
    }
}

#[test]
fn cli_policy_is_complete_instead_of_parser_only() {
    let policy = policy();
    let rule = string(
        keyed_rows(&policy, "special_case_contracts", "case_id")["CLI-COMPLETE-SURFACE"],
        "rule",
    );
    for required in [
        "command",
        "alias",
        "option",
        "environment variable",
        "OsString",
        "invalid-UTF-8",
        "help",
        "error",
        "exit",
        "config",
        "accessibility",
        "interruption",
        "installation",
        "recovery",
    ] {
        assert!(rule.contains(required), "CLI rule missing {required}");
    }
}

#[test]
fn rollback_contract_is_exact_revision_data_and_cleanup_aware() {
    let policy = policy();
    let rollback_value = &policy["rollback_contract"];
    let rollback = object(&policy, "rollback_contract");
    assert!(bool_field(rollback_value, "required_for_replace"));
    assert_eq!(rollback["status_required"].as_str(), Some("PASS"));
    for key in [
        "revision_rule",
        "trigger_rule",
        "artifact_rule",
        "restore_rule",
        "rehearsal_rule",
    ] {
        assert!(
            string(rollback_value, key).len() > 80,
            "{key} must be detailed"
        );
    }
    assert!(
        rollback["revision_rule"]
            .as_str()
            .unwrap()
            .contains("lockfile")
    );
    assert!(
        rollback["artifact_rule"]
            .as_str()
            .unwrap()
            .contains("lossless reverse migrator")
    );
    assert!(
        rollback["restore_rule"]
            .as_str()
            .unwrap()
            .contains("without deleting evidence or user data")
    );
}

#[test]
fn hypothetical_complete_stateless_replace_receipt_is_accepted() {
    let policy = policy();
    let registry = registry();
    let baseline = baseline();
    let receipt = valid_replace_receipt(&policy, &registry, &baseline, "CAP-HEX-CODEC");
    let errors = decision_errors(&policy, &registry, &baseline, &receipt);
    assert!(errors.is_empty(), "decision errors:\n{}", errors.join("\n"));
}

#[test]
fn keep_is_a_successful_no_switch_outcome() {
    let errors = decision_errors(
        &policy(),
        &registry(),
        &baseline(),
        &non_replace_receipt("KEEP"),
    );
    assert!(errors.is_empty(), "KEEP errors:\n{}", errors.join("\n"));
}

#[test]
fn defer_is_a_successful_no_switch_outcome_with_resume_conditions() {
    let errors = decision_errors(
        &policy(),
        &registry(),
        &baseline(),
        &non_replace_receipt("DEFER"),
    );
    assert!(errors.is_empty(), "DEFER errors:\n{}", errors.join("\n"));
}

#[test]
fn blocked_is_not_closeable_and_names_an_owner() {
    let errors = decision_errors(
        &policy(),
        &registry(),
        &baseline(),
        &non_replace_receipt("BLOCKED"),
    );
    assert!(errors.is_empty(), "BLOCKED errors:\n{}", errors.join("\n"));
}

#[test]
fn cutover_rejects_an_unmapped_capability() {
    let policy = policy();
    let registry = registry();
    let baseline = baseline();
    let mut receipt = valid_replace_receipt(&policy, &registry, &baseline, "CAP-HEX-CODEC");
    receipt["affected_capability_ids"] = json!(["CAP-DOES-NOT-EXIST"]);
    let errors = decision_errors(&policy, &registry, &baseline, &receipt);
    assert!(
        errors
            .iter()
            .any(|error| error.contains("unmapped capability"))
    );
}

#[test]
fn cutover_rejects_duplicate_capability_ids() {
    let policy = policy();
    let registry = registry();
    let baseline = baseline();
    let mut receipt = valid_replace_receipt(&policy, &registry, &baseline, "CAP-HEX-CODEC");
    receipt["affected_capability_ids"] = json!(["CAP-HEX-CODEC", "CAP-HEX-CODEC"]);
    let errors = decision_errors(&policy, &registry, &baseline, &receipt);
    assert!(errors.iter().any(|error| error.contains("must be unique")));
}

#[test]
fn cutover_rejects_a_guard_only_capability_as_the_target() {
    let policy = policy();
    let registry = registry();
    let baseline = baseline();
    let mut receipt = valid_replace_receipt(&policy, &registry, &baseline, "CAP-HEX-CODEC");
    receipt["affected_capability_ids"] = json!(["CAP-PUBLIC-API-TOPOLOGY"]);
    let errors = decision_errors(&policy, &registry, &baseline, &receipt);
    assert!(errors.iter().any(|error| error.contains("guard-only")));
}

#[test]
fn cutover_rejects_unknown_or_worse_parity() {
    let policy = policy();
    let registry = registry();
    let baseline = baseline();
    for bad in ["UNKNOWN", "WORSE", "NOT_APPLICABLE"] {
        let mut receipt = valid_replace_receipt(&policy, &registry, &baseline, "CAP-HEX-CODEC");
        receipt["parity_results"][0]["result"] = Value::String(bad.to_owned());
        let errors = decision_errors(&policy, &registry, &baseline, &receipt);
        assert!(
            errors
                .iter()
                .any(|error| error.contains("cannot advance REPLACE")),
            "{bad}: {errors:?}"
        );
    }
}

#[test]
fn cutover_rejects_missing_parity_mode_coverage() {
    let policy = policy();
    let registry = registry();
    let baseline = baseline();
    let mut receipt = valid_replace_receipt(&policy, &registry, &baseline, "CAP-HEX-CODEC");
    receipt["parity_results"]
        .as_array_mut()
        .expect("parity array")
        .pop();
    let errors = decision_errors(&policy, &registry, &baseline, &receipt);
    assert!(
        errors
            .iter()
            .any(|error| error.contains("parity-mode coverage"))
    );
}

#[test]
fn cutover_rejects_missing_or_failed_case_coverage() {
    let policy = policy();
    let registry = registry();
    let baseline = baseline();
    let mut missing = valid_replace_receipt(&policy, &registry, &baseline, "CAP-HEX-CODEC");
    missing["case_results"]
        .as_array_mut()
        .expect("case array")
        .pop();
    assert!(
        decision_errors(&policy, &registry, &baseline, &missing)
            .iter()
            .any(|error| error.contains("case-class coverage"))
    );

    let mut failed = valid_replace_receipt(&policy, &registry, &baseline, "CAP-HEX-CODEC");
    failed["case_results"][0]["outcome"] = json!("FAIL");
    assert!(
        decision_errors(&policy, &registry, &baseline, &failed)
            .iter()
            .any(|error| error.contains("required case must PASS"))
    );
}

#[test]
fn cutover_rejects_missing_or_nonpassing_gate_evidence() {
    let policy = policy();
    let registry = registry();
    let baseline = baseline();
    let mut missing = valid_replace_receipt(&policy, &registry, &baseline, "CAP-HEX-CODEC");
    missing["gate_results"]
        .as_array_mut()
        .expect("gate array")
        .pop();
    assert!(
        decision_errors(&policy, &registry, &baseline, &missing)
            .iter()
            .any(|error| error.contains("required gate coverage"))
    );

    let mut failed = valid_replace_receipt(&policy, &registry, &baseline, "CAP-HEX-CODEC");
    failed["gate_results"][0]["outcome"] = json!("BLOCKED_EXTERNAL");
    assert!(
        decision_errors(&policy, &registry, &baseline, &failed)
            .iter()
            .any(|error| error.contains("required gate outcome is not PASS"))
    );
}

#[test]
fn cutover_rejects_missing_downstream_proof() {
    let policy = policy();
    let registry = registry();
    let baseline = baseline();
    let mut receipt = valid_replace_receipt(&policy, &registry, &baseline, "CAP-HEX-CODEC");
    receipt["downstream_receipts"] = json!([]);
    let errors = decision_errors(&policy, &registry, &baseline, &receipt);
    assert!(
        errors
            .iter()
            .any(|error| error.contains("downstream receipts"))
    );
}

#[test]
fn cutover_rejects_feature_loss_api_narrowing_and_format_rejection() {
    let policy = policy();
    let registry = registry();
    let baseline = baseline();
    for (field, fragment) in [
        ("feature_loss", "lose a feature"),
        ("api_narrowing", "narrow a public"),
        ("format_rejection", "reject a currently accepted format"),
    ] {
        let mut receipt = valid_replace_receipt(&policy, &registry, &baseline, "CAP-HEX-CODEC");
        receipt[field] = json!(true);
        let errors = decision_errors(&policy, &registry, &baseline, &receipt);
        assert!(
            errors.iter().any(|error| error.contains(fragment)),
            "{field}: {errors:?}"
        );
    }
}

#[test]
fn cutover_rejects_unresolved_regressions() {
    let policy = policy();
    let registry = registry();
    let baseline = baseline();
    let mut receipt = valid_replace_receipt(&policy, &registry, &baseline, "CAP-HEX-CODEC");
    receipt["unresolved_regressions"] = json!(["p999 latency regressed"]);
    let errors = decision_errors(&policy, &registry, &baseline, &receipt);
    assert!(
        errors
            .iter()
            .any(|error| error.contains("unresolved regressions"))
    );
}

#[test]
fn cutover_rejects_missing_stateful_migration_or_old_input_preservation() {
    let policy = policy();
    let registry = registry();
    let baseline = baseline();
    let mut missing = valid_replace_receipt(
        &policy,
        &registry,
        &baseline,
        "CAP-PERSISTED-TRACE-SNAPSHOT",
    );
    missing["migration_plan"]["required"] = json!(false);
    assert!(
        decision_errors(&policy, &registry, &baseline, &missing)
            .iter()
            .any(|error| error.contains("requires a migration plan"))
    );

    let mut destructive = valid_replace_receipt(
        &policy,
        &registry,
        &baseline,
        "CAP-PERSISTED-TRACE-SNAPSHOT",
    );
    destructive["migration_plan"]["old_inputs_preserved"] = json!(false);
    destructive["migration_plan"]["deletion_authorized"] = json!(true);
    assert!(
        decision_errors(&policy, &registry, &baseline, &destructive)
            .iter()
            .any(|error| error.contains("preserve old inputs"))
    );
}

#[test]
fn cutover_rejects_incomplete_rollback_even_for_stateless_changes() {
    let policy = policy();
    let registry = registry();
    let baseline = baseline();
    let mut receipt = valid_replace_receipt(&policy, &registry, &baseline, "CAP-HEX-CODEC");
    receipt["rollback_plan"]
        .as_object_mut()
        .expect("rollback object")
        .remove("rehearsal_receipt");
    let errors = decision_errors(&policy, &registry, &baseline, &receipt);
    assert!(
        errors
            .iter()
            .any(|error| error.contains("rollback receipt"))
    );
}

#[test]
fn cutover_rejects_a_silent_unsupported_platform_cell() {
    let policy = policy();
    let registry = registry();
    let baseline = baseline();
    let mut receipt = valid_replace_receipt(&policy, &registry, &baseline, "CAP-SIGNALS");
    receipt["platform_matrix"]["unsupported_required_cells"] = json!(["windows-control-events"]);
    let errors = decision_errors(&policy, &registry, &baseline, &receipt);
    assert!(errors.iter().any(|error| error.contains("platform matrix")));
}

#[test]
fn cutover_rejects_missing_real_service_versions() {
    let policy = policy();
    let registry = registry();
    let baseline = baseline();
    let mut receipt = valid_replace_receipt(&policy, &registry, &baseline, "CAP-KAFKA");
    receipt["service_matrix"]["missing_versions"] = json!(["broker-3.x"]);
    let errors = decision_errors(&policy, &registry, &baseline, &receipt);
    assert!(
        errors
            .iter()
            .any(|error| error.contains("real-service matrix"))
    );
}

#[test]
fn cutover_rejects_incomplete_security_review() {
    let policy = policy();
    let registry = registry();
    let baseline = baseline();
    for field in ["independent_review", "fail_closed", "redaction_verified"] {
        let mut receipt = valid_replace_receipt(&policy, &registry, &baseline, "CAP-TLS-X509");
        receipt["security_review"][field] = json!(false);
        let errors = decision_errors(&policy, &registry, &baseline, &receipt);
        assert!(
            errors.iter().any(|error| error.contains("security review")),
            "{field}: {errors:?}"
        );
    }
}

#[test]
fn cutover_rejects_a_performance_no_win_or_incomplete_axis_matrix() {
    let policy = policy();
    let registry = registry();
    let baseline = baseline();
    for (field, value) in [
        ("status", json!("NO_WIN")),
        ("no_regression", json!(false)),
        ("tracked_axes_complete", json!(false)),
    ] {
        let mut receipt = valid_replace_receipt(&policy, &registry, &baseline, "CAP-SYNC-LOCKS");
        receipt["performance_review"][field] = value;
        let errors = decision_errors(&policy, &registry, &baseline, &receipt);
        assert!(
            errors
                .iter()
                .any(|error| error.contains("performance review")),
            "{field}: {errors:?}"
        );
    }
}

#[test]
fn cutover_rejects_unsafe_or_unretired_oracle_disposition() {
    let policy = policy();
    let registry = registry();
    let baseline = baseline();
    for field in ["graph_safe", "cycle_safe", "expiry_or_retirement_recorded"] {
        let mut receipt = valid_replace_receipt(&policy, &registry, &baseline, "CAP-HEX-CODEC");
        receipt["oracle_disposition"][field] = json!(false);
        let errors = decision_errors(&policy, &registry, &baseline, &receipt);
        assert!(
            errors
                .iter()
                .any(|error| error.contains("oracle disposition")),
            "{field}: {errors:?}"
        );
    }
}

#[test]
fn cutover_rejects_missing_docs_or_owner_signoff() {
    let policy = policy();
    let registry = registry();
    let baseline = baseline();
    let mut no_docs = valid_replace_receipt(&policy, &registry, &baseline, "CAP-HEX-CODEC");
    no_docs["documentation_receipt"]["paths"] = json!([]);
    assert!(
        decision_errors(&policy, &registry, &baseline, &no_docs)
            .iter()
            .any(|error| error.contains("documentation"))
    );

    let mut no_owner = valid_replace_receipt(&policy, &registry, &baseline, "CAP-HEX-CODEC");
    no_owner["owner_signoffs"] = json!([]);
    assert!(
        decision_errors(&policy, &registry, &baseline, &no_owner)
            .iter()
            .any(|error| error.contains("owner signoffs"))
    );
}

#[test]
fn cutover_rejects_a_state_machine_bypass() {
    let policy = policy();
    let registry = registry();
    let baseline = baseline();
    let mut receipt = valid_replace_receipt(&policy, &registry, &baseline, "CAP-HEX-CODEC");
    receipt["state_transition"] = json!({"from": "INCUMBENT_PRIMARY", "to": "REPLACEMENT_PRIMARY"});
    let errors = decision_errors(&policy, &registry, &baseline, &receipt);
    assert!(
        errors
            .iter()
            .any(|error| error.contains("serialized cutover transition"))
    );
}

#[test]
fn cutover_rejects_a_malformed_source_or_stale_time_shape() {
    let policy = policy();
    let registry = registry();
    let baseline = baseline();
    let mut receipt = valid_replace_receipt(&policy, &registry, &baseline, "CAP-HEX-CODEC");
    receipt["source_revision"] = json!("main");
    receipt["evidence_as_of_utc"] = json!("today");
    let errors = decision_errors(&policy, &registry, &baseline, &receipt);
    assert!(
        errors
            .iter()
            .any(|error| error.contains("full hexadecimal commit"))
    );
    assert!(errors.iter().any(|error| error.contains("ISO-8601 UTC")));
}

#[test]
fn missing_capability_binding_is_rejected() {
    let mut policy = policy();
    policy["capability_bindings"]
        .as_array_mut()
        .expect("binding array")
        .pop();
    let errors = policy_errors(&policy, &registry(), &baseline());
    assert!(
        errors
            .iter()
            .any(|error| error.contains("coverage differs"))
    );
}

#[test]
fn registry_state_drift_is_rejected() {
    let mut policy = policy();
    policy["capability_bindings"][0]["registry_cutover_state"] = json!("KEEP_INCUMBENT");
    let errors = policy_errors(&policy, &registry(), &baseline());
    assert!(
        errors
            .iter()
            .any(|error| error.contains("registry cutover state drift"))
    );
}

#[test]
fn unknown_migration_class_is_rejected() {
    let mut policy = policy();
    policy["capability_bindings"][0]["migration_class"] = json!("MYSTERY");
    let errors = policy_errors(&policy, &registry(), &baseline());
    assert!(
        errors
            .iter()
            .any(|error| error.contains("unknown migration class"))
    );
}

#[test]
fn prematurely_authorized_dependency_exit_is_rejected() {
    let mut policy = policy();
    policy["capability_bindings"][0]["dependency_exit_allowed"] = json!(true);
    let errors = policy_errors(&policy, &registry(), &baseline());
    assert!(
        errors
            .iter()
            .any(|error| error.contains("dependency exit must remain disabled"))
    );
}

#[test]
fn broadening_a_required_gate_to_blocked_is_rejected() {
    let mut policy = policy();
    policy["gate_catalog"][0]["advance_outcomes"] = json!(["PASS", "BLOCKED_EXTERNAL"]);
    let errors = policy_errors(&policy, &registry(), &baseline());
    assert!(
        errors
            .iter()
            .any(|error| error.contains("only PASS may advance"))
    );
}

#[test]
fn enabling_a_forbidden_transition_is_rejected() {
    let mut policy = policy();
    policy["cutover_state_machine"]["transitions"]
        .as_array_mut()
        .expect("transition array")
        .push(json!({
            "from": "INCUMBENT_PRIMARY",
            "to": "REPLACEMENT_PRIMARY",
            "required_gate_ids": [],
            "production_switch": true
        }));
    let errors = policy_errors(&policy, &registry(), &baseline());
    assert!(
        errors
            .iter()
            .any(|error| error.contains("forbidden transition is enabled"))
    );
}

#[test]
fn required_field_taxonomy_drift_is_rejected() {
    let mut policy = policy();
    policy["decision_receipt_required_fields"]
        .as_array_mut()
        .expect("field array")
        .pop();
    let errors = policy_errors(&policy, &registry(), &baseline());
    assert!(
        errors
            .iter()
            .any(|error| error.contains("decision receipt field inventory drift"))
    );
}

#[test]
fn validation_owners_and_paths_are_live_and_scoped() {
    let policy = policy();
    let validation = object(&policy, "validation");
    assert_eq!(validation["contract_path"].as_str(), Some(TEST_PATH));
    assert_eq!(validation["documentation_path"].as_str(), Some(DOC_PATH));
    assert_eq!(validation["runner_path"].as_str(), Some(RUNNER_PATH));
    for path_key in ["contract_path", "documentation_path", "runner_path"] {
        let path = validation[path_key].as_str().expect("validation path");
        assert!(repo_file_exists(path), "{path_key} must exist: {path}");
    }
    let live_ids = live_bead_ids();
    for owner_key in [
        "aggregate_e2e_owner",
        "aggregate_negative_fixture_owner",
        "graph_audit_owner",
        "phase_one_signoff_owner",
    ] {
        let owner = validation[owner_key].as_str().expect("owner string");
        assert!(live_ids.contains(owner), "{owner_key} must exist: {owner}");
    }
    assert!(
        validation["proof_command"]
            .as_str()
            .unwrap()
            .starts_with("RCH_REQUIRE_REMOTE=1 rch exec --")
    );
    assert!(
        validation["no_claim_boundary"]
            .as_str()
            .unwrap()
            .contains("does not prove a candidate has parity")
    );
}

#[test]
fn runner_contract_is_remote_only_logged_redacted_and_replayable() {
    let policy = policy();
    let validation = object(&policy, "validation");
    let runner = read_repo_file(RUNNER_PATH);
    for required in [
        "RCH_REQUIRE_REMOTE",
        "rch exec --base HEAD --clean-overlay --no-overlay",
        "CARGO_TARGET_DIR",
        "events.ndjson",
        "summary.json",
        "stdout.log",
        "stderr.log",
        "provenance.json",
        "replay.sh",
        "redaction_status",
        "cleanup_status",
        "residual_children",
        "fixture_manifest",
        "fixture_digest",
        "rch_worker",
        "generated_paths",
        "BLOCKED_EXTERNAL",
        "refusing to overwrite retained evidence directory",
    ] {
        assert!(runner.contains(required), "runner missing {required}");
    }
    for scenario in ["contract", "catalog"] {
        assert!(
            runner.contains(scenario),
            "runner missing scenario {scenario}"
        );
    }
    let minimum = validation["minimum_contract_tests"]
        .as_u64()
        .expect("minimum contract tests");
    assert!(minimum >= 30);
    assert!(runner.contains(&format!("MINIMUM_TESTS={minimum}")));
    assert!(!runner.contains("cargo test") || runner.contains("rch exec"));
}

#[test]
fn documentation_generated_summary_matches_canonical_artifact() {
    let policy = policy();
    let bindings = array(&policy, "capability_bindings");
    let target_count = bindings
        .iter()
        .filter(|row| string(row, "binding_role") == "CUTOVER_TARGET")
        .count();
    let guard_count = bindings.len() - target_count;
    let current_states = bindings.iter().fold(BTreeMap::new(), |mut counts, row| {
        *counts
            .entry(string(row, "registry_cutover_state"))
            .or_insert(0usize) += 1;
        counts
    });
    let expected = format!(
        "- Artifact: `dependency-cutover-policy-v1` (schema 1)\n\
         - Coverage: {} capabilities; {} cutover targets; {} cross-cutting guards.\n\
         - Policy: {} terminal verdicts; {} gates; {} migration classes; {} special-case contracts.\n\
         - Current registry states: BLOCKED_PENDING_EVIDENCE={}; KEEP_INCUMBENT={}; NOT_A_CUTOVER={}.",
        bindings.len(),
        target_count,
        guard_count,
        array(&policy, "terminal_verdicts").len(),
        array(&policy, "gate_catalog").len(),
        array(&policy, "migration_classes").len(),
        array(&policy, "special_case_contracts").len(),
        current_states["BLOCKED_PENDING_EVIDENCE"],
        current_states["KEEP_INCUMBENT"],
        current_states["NOT_A_CUTOVER"],
    );
    let docs = read_repo_file(DOC_PATH);
    let start = docs
        .find("<!-- BEGIN GENERATED CUTOVER POLICY SUMMARY -->")
        .expect("generated summary start");
    let end = docs
        .find("<!-- END GENERATED CUTOVER POLICY SUMMARY -->")
        .expect("generated summary end");
    let generated = docs[start..end]
        .lines()
        .skip(1)
        .collect::<Vec<_>>()
        .join("\n")
        .trim()
        .to_owned();
    assert_eq!(generated, expected);
}

#[test]
fn durable_policy_artifact_is_registered_in_governance_ledger() {
    let ledger = parse_repo_json(GOVERNANCE_LEDGER_PATH);
    let rows = keyed_rows(&ledger, "rows", "artifact_id");
    let row = rows
        .get("dependency-cutover-policy-v1")
        .expect("governance ledger row");
    assert_eq!(string(row, "path"), ARTIFACT_PATH);
    assert_eq!(string(row, "path_status"), "tracked");
    assert_eq!(string(row, "owning_bead"), BEAD_ID);
    assert_eq!(
        string_set(row, "checked_by_tests"),
        BTreeSet::from([TEST_PATH.to_owned()])
    );
    assert!(string_set(row, "no_claim_boundaries").len() >= 3);
    assert!(string_set(row, "no_claim_boundaries").contains("does_not_authorize_cutover"));
}

#[test]
fn canonical_artifact_contains_no_placeholders_or_deletion_authority() {
    let raw = read_repo_file(ARTIFACT_PATH);
    for forbidden in [
        "TODO",
        "TBD",
        "FIXME",
        "planned://",
        "\"dependency_exit_allowed\": true",
    ] {
        assert!(!raw.contains(forbidden), "artifact contains {forbidden}");
    }
    assert!(raw.contains("\"no_deletion_rule\""));
}
