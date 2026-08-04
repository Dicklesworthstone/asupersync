//! Fail-closed VER A1 evidence-matrix contract.
//!
//! Bead: asupersync-dep-p1-foundations-upksjk.6.1
//! Scenario: dependency_verification_matrix_contract_v1
//! Fixture: artifacts/dependency_verification_matrix_v1.json

#![allow(missing_docs)]

use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::process::Command;

const BEAD_ID: &str = "asupersync-dep-p1-foundations-upksjk.6.1";
const PROGRAM_ID: &str = "asupersync-ir2uf0";
const ARTIFACT_PATH: &str = "artifacts/dependency_verification_matrix_v1.json";
const REGISTRY_PATH: &str = "artifacts/dependency_capability_registry_v1.json";
const TRACKER_PATH: &str = ".beads/issues.jsonl";
const DOC_PATH: &str = "docs/dependency_verification_matrix.md";
const GENERATOR_PATH: &str = "src/bin/dependency_verification_matrix.rs";
const GENERATED_BINARY: &str = env!("CARGO_BIN_EXE_dependency_verification_matrix");

const BASE_CASES: &[&str] = &[
    "happy_path",
    "empty_boundary",
    "maximum_overflow",
    "malformed_error",
    "resource_bound",
    "regression",
];
const PARSER_CASES: &[&str] = &[
    "truncation",
    "invalid_state",
    "round_trip",
    "independent_vector",
];
const CONCURRENCY_CASES: &[&str] = &[
    "cancellation",
    "race_shutdown",
    "task_leak",
    "obligation_leak",
    "loser_drain",
    "quiescence",
];
const SECURITY_CASES: &[&str] = &[
    "security_misuse",
    "authentication_failure",
    "secret_redaction",
];
const PUBLIC_CASES: &[&str] = &["downstream_compile", "downstream_runtime"];

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn read_repo_file(path: &str) -> String {
    std::fs::read_to_string(repo_root().join(path))
        .unwrap_or_else(|error| panic!("failed to read {path}: {error}"))
}

fn parse_json(path: &str) -> Value {
    serde_json::from_str(&read_repo_file(path))
        .unwrap_or_else(|error| panic!("{path} must be valid JSON: {error}"))
}

fn artifact() -> Value {
    parse_json(ARTIFACT_PATH)
}

fn array<'a>(value: &'a Value, key: &str) -> Option<&'a [Value]> {
    value.get(key).and_then(Value::as_array).map(Vec::as_slice)
}

fn string<'a>(value: &'a Value, key: &str) -> Option<&'a str> {
    value.get(key).and_then(Value::as_str)
}

fn strings(value: &Value, key: &str) -> BTreeSet<String> {
    array(value, key)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(ToOwned::to_owned)
        .collect()
}

fn nonempty_string(value: &Value, key: &str, context: &str, errors: &mut Vec<String>) {
    if string(value, key).is_none_or(|entry| entry.trim().is_empty()) {
        errors.push(format!("{context}: {key} must be a nonempty string"));
    }
}

fn nonempty_strings(value: &Value, key: &str, context: &str, errors: &mut Vec<String>) {
    let Some(entries) = array(value, key) else {
        errors.push(format!("{context}: {key} must be an array"));
        return;
    };
    if entries.is_empty()
        || entries
            .iter()
            .any(|entry| entry.as_str().is_none_or(|text| text.trim().is_empty()))
    {
        errors.push(format!("{context}: {key} must contain nonempty strings"));
    }
}

/// Disposition tokens marking a closed tracker issue as superseded by a
/// canonical successor. Must stay in sync with `SUPERSEDED_DUPLICATE_TOKENS`
/// in `src/bin/dependency_verification_matrix.rs`, which is the generator side
/// of this same rule.
const SUPERSEDED_DUPLICATE_TOKENS: [&str; 2] = ["superseded", "duplicate"];

/// Returns true when `reason` contains a disposition token as a whole ASCII
/// word.
///
/// Deliberately not a naked `contains`: substring matching fails open, silently
/// dropping a bead from required verification coverage whenever a longer word
/// embeds one of these tokens. `asupersync-ym2wtv.1` closed as a DEFER decision
/// reading "GB-03 duplicated-runtime finding is decisive", and
/// `contains("duplicate")` matched inside "duplicated" (br-asupersync-290bci).
fn contains_superseded_duplicate_token(reason: &str) -> bool {
    let reason = reason.to_ascii_lowercase();
    SUPERSEDED_DUPLICATE_TOKENS.iter().any(|token| {
        reason.match_indices(token).any(|(start, matched)| {
            let before_ok = reason[..start]
                .chars()
                .next_back()
                .is_none_or(|character| !character.is_ascii_alphanumeric());
            let after_ok = reason[start + matched.len()..]
                .chars()
                .next()
                .is_none_or(|character| !character.is_ascii_alphanumeric());
            before_ok && after_ok
        })
    })
}

#[test]
fn superseded_duplicate_tokens_match_whole_words_only() {
    // Genuine dispositions still exclude the bead from required coverage.
    assert!(contains_superseded_duplicate_token(
        "DEP-ADR-009/010/012 resolved and frozen; plan superseded"
    ));
    assert!(contains_superseded_duplicate_token(
        "closed: duplicate of x"
    ));
    assert!(contains_superseded_duplicate_token("Superseded."));
    assert!(contains_superseded_duplicate_token("(duplicate)"));

    // Prose that merely embeds a token must NOT drop coverage. The first case
    // is the live regression: asupersync-ym2wtv.1 is a DEFER decision.
    assert!(!contains_superseded_duplicate_token(
        "GB-03 duplicated-runtime finding is decisive; terminal outcome DEFER, incumbent stands"
    ));
    assert!(!contains_superseded_duplicate_token(
        "deduplicate the evidence rows"
    ));
    assert!(!contains_superseded_duplicate_token("duplicates"));
    assert!(!contains_superseded_duplicate_token("superseding"));
    assert!(!contains_superseded_duplicate_token(""));
}

fn tracker_matrix_ids() -> BTreeSet<String> {
    read_repo_file(TRACKER_PATH)
        .lines()
        .filter(|line| !line.trim().is_empty())
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .filter(|issue| {
            issue
                .get("labels")
                .and_then(Value::as_array)
                .is_some_and(|labels| {
                    labels
                        .iter()
                        .any(|label| label.as_str() == Some("dep-plan"))
                })
                && issue.get("issue_type").and_then(Value::as_str) != Some("epic")
                && !(issue.get("status").and_then(Value::as_str) == Some("closed")
                    && issue
                        .get("close_reason")
                        .and_then(Value::as_str)
                        .is_some_and(contains_superseded_duplicate_token))
        })
        .filter_map(|issue| {
            issue
                .get("id")
                .and_then(Value::as_str)
                .map(ToOwned::to_owned)
        })
        .collect()
}

fn require_cases(
    row: &Value,
    cases: &[&str],
    reason: &str,
    bead_id: &str,
    errors: &mut Vec<String>,
) {
    let actual = strings(row, "required_case_classes");
    for case in cases {
        if !actual.contains(*case) {
            errors.push(format!("{bead_id}: {reason} requires case class {case}"));
        }
    }
}

fn has_plan_class(row: &Value, class: &str) -> bool {
    array(row, "evidence_plans")
        .into_iter()
        .flatten()
        .any(|plan| string(plan, "class") == Some(class))
}

fn validate_plan(
    row: &Value,
    plan: &Value,
    required_cases: &BTreeSet<String>,
    errors: &mut Vec<String>,
) {
    let bead_id = string(row, "bead_id").unwrap_or("<missing-bead>");
    let evidence_id = string(plan, "evidence_id").unwrap_or("<missing-evidence>");
    let context = format!("{bead_id}/{evidence_id}");
    for key in [
        "evidence_id",
        "class",
        "test_file",
        "seed_or_fixture_id",
        "command",
        "artifact_root",
        "expected_outcome",
        "evidence_owner",
        "plan_state",
    ] {
        nonempty_string(plan, key, &context, errors);
    }
    for key in [
        "stable_test_names",
        "feature_requirements",
        "covers_case_classes",
    ] {
        nonempty_strings(plan, key, &context, errors);
    }
    if string(plan, "evidence_owner") != Some(bead_id) {
        errors.push(format!("{context}: evidence_owner must be the matrix bead"));
    }
    if string(plan, "plan_state") != Some("PLANNED_BLOCKING") {
        errors.push(format!(
            "{context}: plan_state must remain PLANNED_BLOCKING"
        ));
    }
    if string(plan, "expected_outcome") != Some("pass") {
        errors.push(format!("{context}: expected_outcome must be pass"));
    }
    let class = string(plan, "class").unwrap_or("");
    let command = string(plan, "command").unwrap_or("");
    if class != "e2e" && !command.starts_with("RCH_REQUIRE_REMOTE=1 rch exec -- ") {
        errors.push(format!(
            "{context}: cargo-backed command must be remote-required"
        ));
    }
    if class == "e2e" && command != "scripts/run_all_e2e.sh --suite dependency-sovereignty" {
        errors.push(format!(
            "{context}: e2e command must use the canonical dependency-sovereignty suite"
        ));
    }
    if matches!(class, "unit" | "contract") {
        let covered = strings(plan, "covers_case_classes");
        for required in required_cases {
            if !covered.contains(required) {
                errors.push(format!(
                    "{context}: local plan must cover required case {required}"
                ));
            }
        }
    }

    if class == "fuzz" {
        let Some(contract) = plan.get("class_contract").and_then(Value::as_object) else {
            errors.push(format!("{context}: fuzz class_contract is required"));
            return;
        };
        if contract
            .get("max_total_time_seconds")
            .and_then(Value::as_u64)
            .is_none_or(|bound| bound == 0 || bound > 3_600)
        {
            errors.push(format!(
                "{context}: fuzz max_total_time_seconds must be bounded"
            ));
        }
        if contract
            .get("max_input_bytes")
            .and_then(Value::as_u64)
            .is_none_or(|bound| bound == 0 || bound > 16 * 1_048_576)
        {
            errors.push(format!("{context}: fuzz max_input_bytes must be bounded"));
        }
        for key in [
            "corpus_owner",
            "corpus_path",
            "crash_artifact_path",
            "crash_minimization_command",
        ] {
            if contract
                .get(key)
                .and_then(Value::as_str)
                .is_none_or(|entry| entry.trim().is_empty())
            {
                errors.push(format!("{context}: fuzz {key} is required"));
            }
        }
        if contract
            .get("oracle_retirement_independent")
            .and_then(Value::as_bool)
            != Some(true)
        {
            errors.push(format!(
                "{context}: fuzz oracle_retirement_independent must be true"
            ));
        }
        if contract
            .get("oracle_evidence_may_authorize_cutover")
            .and_then(Value::as_bool)
            != Some(false)
        {
            errors.push(format!(
                "{context}: fuzz oracle evidence may not authorize cutover"
            ));
        }
    }

    if class == "downstream" {
        let Some(contract) = plan.get("class_contract").and_then(Value::as_object) else {
            errors.push(format!("{context}: downstream class_contract is required"));
            return;
        };
        for key in [
            "compile_fixture_required",
            "runtime_fixture_required",
            "public_only",
            "test_internals_forbidden",
        ] {
            if contract.get(key).and_then(Value::as_bool) != Some(true) {
                errors.push(format!("{context}: downstream {key} must be true"));
            }
        }
    }

    if class == "lab" {
        let Some(contract) = plan.get("class_contract") else {
            errors.push(format!("{context}: lab class_contract is required"));
            return;
        };
        let oracles = strings(contract, "required_oracles");
        for oracle in [
            "task_leak",
            "obligation_leak",
            "loser_drain",
            "cancellation_protocol",
            "quiescence",
        ] {
            if !oracles.contains(oracle) {
                errors.push(format!("{context}: lab plan requires oracle {oracle}"));
            }
        }
        if contract.get("virtual_time").and_then(Value::as_bool) != Some(true) {
            errors.push(format!("{context}: lab plan must use virtual time"));
        }
    }
}

fn validate(value: &Value) -> Vec<String> {
    let mut errors = Vec::new();
    if value.get("schema_version").and_then(Value::as_u64) != Some(1) {
        errors.push("schema_version must be 1".to_owned());
    }
    if string(value, "artifact_id") != Some("dependency-verification-matrix-v1") {
        errors.push("artifact_id must be dependency-verification-matrix-v1".to_owned());
    }
    if string(value, "program_id") != Some(PROGRAM_ID) {
        errors.push(format!("program_id must be {PROGRAM_ID}"));
    }
    if string(value, "bead_id") != Some(BEAD_ID) {
        errors.push(format!("bead_id must be {BEAD_ID}"));
    }
    nonempty_string(value, "purpose", "artifact", &mut errors);

    let mut known_capabilities = BTreeSet::new();
    let mut known_invariants = BTreeSet::new();
    let Some(capability_rows) = array(value, "capability_invariants") else {
        errors.push("capability_invariants must be an array".to_owned());
        return errors;
    };
    for row in capability_rows {
        let capability_id = string(row, "capability_id").unwrap_or("<missing-capability>");
        if !known_capabilities.insert(capability_id.to_owned()) {
            errors.push(format!(
                "duplicate capability invariant row {capability_id}"
            ));
        }
        let Some(invariants) = array(row, "invariants") else {
            errors.push(format!("{capability_id}: invariants must be an array"));
            continue;
        };
        if invariants.is_empty() {
            errors.push(format!("{capability_id}: invariants may not be empty"));
        }
        for invariant in invariants {
            let invariant_id = string(invariant, "invariant_id").unwrap_or("<missing-invariant>");
            if !known_invariants.insert(invariant_id.to_owned()) {
                errors.push(format!("duplicate invariant_id {invariant_id}"));
            }
            nonempty_string(invariant, "kind", invariant_id, &mut errors);
            nonempty_string(invariant, "statement", invariant_id, &mut errors);
        }
    }

    let registry_ids = parse_json(REGISTRY_PATH)
        .get("capabilities")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|row| string(row, "capability_id").map(ToOwned::to_owned))
        .collect::<BTreeSet<_>>();
    if known_capabilities != registry_ids {
        errors.push("capability invariant rows must exactly cover the registry".to_owned());
    }

    let Some(matrix) = array(value, "matrix") else {
        errors.push("matrix must be an array".to_owned());
        return errors;
    };
    let mut matrix_ids = BTreeSet::new();
    let mut evidence_counts = BTreeMap::<String, usize>::new();
    for row in matrix {
        let bead_id = string(row, "bead_id").unwrap_or("<missing-bead>");
        if !matrix_ids.insert(bead_id.to_owned()) {
            errors.push(format!("duplicate matrix bead {bead_id}"));
        }
        for key in [
            "bead_id",
            "title",
            "issue_type",
            "role",
            "cutover_state",
            "no_claim_boundary",
        ] {
            nonempty_string(row, key, bead_id, &mut errors);
        }
        for key in [
            "capability_ids",
            "invariant_ids",
            "risk_tags",
            "feature_requirements",
            "target_requirements",
            "required_case_classes",
            "evidence_plans",
        ] {
            if key == "evidence_plans" {
                if array(row, key).is_none_or(|entries| entries.is_empty()) {
                    errors.push(format!("{bead_id}: evidence_plans may not be empty"));
                }
            } else {
                nonempty_strings(row, key, bead_id, &mut errors);
            }
        }
        if !matches!(
            string(row, "role"),
            Some("implementation" | "architecture" | "verification" | "decision")
        ) {
            errors.push(format!("{bead_id}: unsupported role"));
        }
        if string(row, "cutover_state") != Some("BLOCKED_PENDING_EVIDENCE") {
            errors.push(format!("{bead_id}: planned matrix row must block cutover"));
        }

        for capability_id in strings(row, "capability_ids") {
            if !known_capabilities.contains(&capability_id) {
                errors.push(format!(
                    "{bead_id}: unknown capability reference {capability_id}"
                ));
            }
        }
        for invariant_id in strings(row, "invariant_ids") {
            if !known_invariants.contains(&invariant_id) {
                errors.push(format!(
                    "{bead_id}: unknown invariant reference {invariant_id}"
                ));
            }
        }

        require_cases(row, BASE_CASES, "all rows", bead_id, &mut errors);
        let risks = strings(row, "risk_tags");
        if risks.contains("parser_codec") {
            require_cases(row, PARSER_CASES, "parser_codec", bead_id, &mut errors);
        }
        if risks.contains("concurrency") {
            require_cases(row, CONCURRENCY_CASES, "concurrency", bead_id, &mut errors);
            if !has_plan_class(row, "lab") {
                errors.push(format!("{bead_id}: concurrency risk requires lab evidence"));
            }
        }
        if risks.contains("security") {
            require_cases(row, SECURITY_CASES, "security", bead_id, &mut errors);
        }
        if risks.contains("public_generic") {
            require_cases(row, PUBLIC_CASES, "public_generic", bead_id, &mut errors);
            if !has_plan_class(row, "downstream") {
                errors.push(format!(
                    "{bead_id}: public_generic risk requires downstream compile/runtime evidence"
                ));
            }
        }
        if risks.contains("property") && !has_plan_class(row, "property") {
            errors.push(format!(
                "{bead_id}: property risk requires property evidence"
            ));
        }
        if risks.contains("fuzz") && !has_plan_class(row, "fuzz") {
            errors.push(format!("{bead_id}: fuzz risk requires fuzz evidence"));
        }
        if risks.contains("user_journey") && !has_plan_class(row, "e2e") {
            errors.push(format!(
                "{bead_id}: user_journey risk requires no-mock e2e evidence"
            ));
        }

        let required_cases = strings(row, "required_case_classes");
        if let Some(plans) = array(row, "evidence_plans") {
            for plan in plans {
                if let Some(class) = string(plan, "class") {
                    *evidence_counts.entry(class.to_owned()).or_default() += 1;
                }
                validate_plan(row, plan, &required_cases, &mut errors);
            }
        }
    }

    if matrix_ids != tracker_matrix_ids() {
        let tracker_ids = tracker_matrix_ids();
        let missing = tracker_ids
            .difference(&matrix_ids)
            .cloned()
            .collect::<Vec<_>>();
        let extra = matrix_ids
            .difference(&tracker_ids)
            .cloned()
            .collect::<Vec<_>>();
        errors.push(format!(
            "matrix bead IDs must exactly cover every non-epic dep-plan tracker issue; missing={missing:?} extra={extra:?}"
        ));
    }
    let expected_counts = value.get("counts").and_then(Value::as_object);
    if expected_counts
        .and_then(|counts| counts.get("matrix_beads"))
        .and_then(Value::as_u64)
        != Some(matrix.len() as u64)
    {
        errors.push("counts.matrix_beads must match matrix length".to_owned());
    }
    if expected_counts
        .and_then(|counts| counts.get("evidence_plans"))
        .and_then(Value::as_u64)
        != Some(evidence_counts.values().sum::<usize>() as u64)
    {
        errors.push("counts.evidence_plans must match evidence plan rows".to_owned());
    }
    errors
}

fn assert_invalid(mutated: Value, expected_fragment: &str) {
    let errors = validate(&mutated);
    assert!(
        errors.iter().any(|error| error.contains(expected_fragment)),
        "expected error containing {expected_fragment:?}; got {errors:#?}"
    );
}

fn first_row_with_risk_mut<'a>(value: &'a mut Value, risk: &str) -> &'a mut Value {
    value
        .get_mut("matrix")
        .and_then(Value::as_array_mut)
        .and_then(|rows| {
            rows.iter_mut()
                .find(|row| strings(row, "risk_tags").contains(risk))
        })
        .unwrap_or_else(|| panic!("artifact must include a {risk} row"))
}

fn remove_required_case(row: &mut Value, case: &str) {
    let cases = row
        .get_mut("required_case_classes")
        .and_then(Value::as_array_mut)
        .expect("required_case_classes");
    cases.retain(|entry| entry.as_str() != Some(case));
}

#[test]
fn canonical_artifact_is_current_and_valid() {
    let value = artifact();
    let errors = validate(&value);
    assert!(errors.is_empty(), "matrix contract errors:\n{errors:#?}");

    let output = Command::new(GENERATED_BINARY)
        .arg("--render")
        .current_dir(repo_root())
        .output()
        .expect("run dependency_verification_matrix --render");
    assert!(
        output.status.success(),
        "generator failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8(output.stdout).expect("generator output must be UTF-8"),
        read_repo_file(ARTIFACT_PATH),
        "canonical artifact must exactly match deterministic generator output"
    );
}

#[test]
fn canonical_sources_and_docs_are_discoverable() {
    for path in [
        ARTIFACT_PATH,
        REGISTRY_PATH,
        TRACKER_PATH,
        DOC_PATH,
        GENERATOR_PATH,
    ] {
        assert!(repo_root().join(path).is_file(), "missing {path}");
    }
    let doc = read_repo_file(DOC_PATH);
    for marker in [
        BEAD_ID,
        ARTIFACT_PATH,
        "PLANNED_BLOCKING",
        "dependency-sovereignty",
        "No-claim boundary",
    ] {
        assert!(doc.contains(marker), "{DOC_PATH} missing marker {marker}");
    }
}

#[test]
fn negative_missing_base_case_fails_closed() {
    for case in BASE_CASES {
        let mut value = artifact();
        let row = value
            .get_mut("matrix")
            .and_then(Value::as_array_mut)
            .and_then(|rows| rows.first_mut())
            .expect("matrix row");
        let bead_id = string(row, "bead_id").expect("bead id").to_owned();
        remove_required_case(row, case);
        assert_invalid(
            value,
            &format!("{bead_id}: all rows requires case class {case}"),
        );
    }
}

#[test]
fn negative_missing_parser_edge_fails_closed() {
    let mut value = artifact();
    remove_required_case(
        first_row_with_risk_mut(&mut value, "parser_codec"),
        "truncation",
    );
    assert_invalid(value, "parser_codec requires case class truncation");
}

#[test]
fn negative_missing_concurrency_oracle_cases_fail_closed() {
    let mut value = artifact();
    remove_required_case(
        first_row_with_risk_mut(&mut value, "concurrency"),
        "quiescence",
    );
    assert_invalid(value, "concurrency requires case class quiescence");
}

#[test]
fn negative_missing_security_case_fails_closed() {
    let mut value = artifact();
    remove_required_case(
        first_row_with_risk_mut(&mut value, "security"),
        "secret_redaction",
    );
    assert_invalid(value, "security requires case class secret_redaction");
}

#[test]
fn negative_public_generic_without_downstream_fixture_fails_closed() {
    let mut value = artifact();
    let row = first_row_with_risk_mut(&mut value, "public_generic");
    row.get_mut("evidence_plans")
        .and_then(Value::as_array_mut)
        .expect("evidence plans")
        .retain(|plan| string(plan, "class") != Some("downstream"));
    assert_invalid(value, "requires downstream compile/runtime evidence");
}

#[test]
fn negative_fuzz_without_bounds_or_minimization_fails_closed() {
    for key in [
        "max_total_time_seconds",
        "max_input_bytes",
        "corpus_owner",
        "crash_minimization_command",
        "oracle_retirement_independent",
    ] {
        let mut value = artifact();
        let row = first_row_with_risk_mut(&mut value, "fuzz");
        let fuzz = row
            .get_mut("evidence_plans")
            .and_then(Value::as_array_mut)
            .and_then(|plans| {
                plans
                    .iter_mut()
                    .find(|plan| string(plan, "class") == Some("fuzz"))
            })
            .expect("fuzz plan");
        fuzz.get_mut("class_contract")
            .and_then(Value::as_object_mut)
            .expect("fuzz class contract")
            .remove(key);
        assert_invalid(value, key);
    }
}

#[test]
fn negative_unknown_invariant_and_duplicate_bead_fail_closed() {
    let mut unknown = artifact();
    unknown
        .get_mut("matrix")
        .and_then(Value::as_array_mut)
        .and_then(|rows| rows.first_mut())
        .and_then(|row| row.get_mut("invariant_ids"))
        .and_then(Value::as_array_mut)
        .expect("invariant ids")
        .push(Value::String("CAP-UNKNOWN::input".to_owned()));
    assert_invalid(unknown, "unknown invariant reference");

    let mut duplicate = artifact();
    let rows = duplicate
        .get_mut("matrix")
        .and_then(Value::as_array_mut)
        .expect("matrix");
    let first = rows[0].clone();
    rows.push(first);
    assert_invalid(duplicate, "duplicate matrix bead");
}

#[test]
fn negative_planned_evidence_cannot_be_promoted_or_cut_over() {
    let mut promoted = artifact();
    let row = promoted
        .get_mut("matrix")
        .and_then(Value::as_array_mut)
        .and_then(|rows| rows.first_mut())
        .expect("matrix row");
    row.get_mut("evidence_plans")
        .and_then(Value::as_array_mut)
        .and_then(|plans| plans.first_mut())
        .and_then(Value::as_object_mut)
        .expect("evidence plan")
        .insert("plan_state".to_owned(), Value::String("PASS".to_owned()));
    assert_invalid(promoted, "plan_state must remain PLANNED_BLOCKING");

    let mut cutover = artifact();
    cutover
        .get_mut("matrix")
        .and_then(Value::as_array_mut)
        .and_then(|rows| rows.first_mut())
        .and_then(Value::as_object_mut)
        .expect("matrix row")
        .insert(
            "cutover_state".to_owned(),
            Value::String("APPROVED".to_owned()),
        );
    assert_invalid(cutover, "planned matrix row must block cutover");
}
