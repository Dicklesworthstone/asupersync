//! Fail-closed regex/privacy capability inventory contract.
//!
//! Bead: asupersync-5z2scg.8.1
//! Scenario: regex-privacy-capability-inventory-contract
//! Fixture: artifacts/regex_privacy_capability_inventory_v1.json
//!
//! This proves source-pinned public surface, syntax, field-policy, detector,
//! bounded resource, concurrency, downstream, privacy-threat, marginal-graph,
//! ownership, and documentation inventories. It does not prove performance,
//! production multi-signal wiring, a real collector journey, general scanner
//! equivalence, or permission to remove the incumbent dependency.

#![allow(missing_docs)]

use asupersync::observability::LogLevel;
use asupersync::observability::otel::{OtlpLogRecord, PrivacyConfig, SpanConfig};
use regex::Regex as IncumbentRegex;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::path::PathBuf;
use std::sync::Arc;

const ARTIFACT_PATH: &str = "artifacts/regex_privacy_capability_inventory_v1.json";
const DOC_PATH: &str = "docs/regex_privacy_capability_inventory.md";
const ADR_PATH: &str = "docs/adr/dep_plan_adr_012_regex_privacy.md";
const CAPABILITY_REGISTRY_PATH: &str = "artifacts/dependency_capability_registry_v1.json";
const BASELINE_PATH: &str = "artifacts/dependency_capability_baseline_v1.json";
const MARGINAL_LEDGER_PATH: &str = "artifacts/dependency_marginal_ledger_v1.json";
const API_SURFACE_MAP_PATH: &str = "artifacts/api_surface_map_v1.json";
const PRIVATE_API_MAP_PATH: &str = "artifacts/regex_private_compile_api_map_v1.json";
const BEAD_ID: &str = "asupersync-5z2scg.8.1";
const PROGRAM_ID: &str = "asupersync-ir2uf0";
const CAPABILITY_ID: &str = "CAP-REGEX-PRIVACY";
const ADR_ID: &str = "DEP-ADR-012";
const BASELINE_REVISION: &str = "23c5ac4074901349fba93617ef11ed5360d3dc61";
const AUTHORITY_REVISION: &str = "909e709c61fe6fbf7e8fbe52c9f355e7ab773992";
const DOC_BEGIN: &str = "<!-- BEGIN REGEX PRIVACY CAPABILITY INVENTORY -->";
const DOC_END: &str = "<!-- END REGEX PRIVACY CAPABILITY INVENTORY -->";

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn read_repo_file(path: &str) -> String {
    std::fs::read_to_string(repo_root().join(path))
        .unwrap_or_else(|error| panic!("failed to read {path}: {error}"))
}

fn read_repo_bytes(path: &str) -> Vec<u8> {
    std::fs::read(repo_root().join(path))
        .unwrap_or_else(|error| panic!("failed to read {path}: {error}"))
}

fn parse_repo_json(path: &str) -> Value {
    serde_json::from_str(&read_repo_file(path))
        .unwrap_or_else(|error| panic!("{path} must be valid JSON: {error}"))
}

fn artifact() -> Value {
    parse_repo_json(ARTIFACT_PATH)
}

fn array<'a>(value: &'a Value, key: &str) -> &'a Vec<Value> {
    value
        .get(key)
        .and_then(Value::as_array)
        .unwrap_or_else(|| panic!("{key} must be an array"))
}

fn object<'a>(value: &'a Value, key: &str) -> &'a serde_json::Map<String, Value> {
    value
        .get(key)
        .and_then(Value::as_object)
        .unwrap_or_else(|| panic!("{key} must be an object"))
}

fn text<'a>(value: &'a Value, key: &str) -> &'a str {
    value
        .get(key)
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("{key} must be a string"))
}

fn row_ids(rows: &[Value], key: &str) -> BTreeSet<String> {
    rows.iter().map(|row| text(row, key).to_owned()).collect()
}

fn string_set(value: &Value, key: &str) -> BTreeSet<String> {
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

fn find_row<'a>(rows: &'a [Value], key: &str, expected: &str) -> &'a Value {
    rows.iter()
        .find(|row| row.get(key).and_then(Value::as_str) == Some(expected))
        .unwrap_or_else(|| panic!("missing {key}={expected}"))
}

fn validate_no_unknown(value: &Value, path: &str) -> Result<(), String> {
    match value {
        Value::String(state) if state == "UNKNOWN" => {
            return Err(format!("{path} must not be UNKNOWN"));
        }
        Value::Array(values) => {
            for (index, child) in values.iter().enumerate() {
                validate_no_unknown(child, &format!("{path}[{index}]"))?;
            }
        }
        Value::Object(values) => {
            for (key, child) in values {
                validate_no_unknown(child, &format!("{path}.{key}"))?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn checked_array<'a>(value: &'a Value, key: &str) -> Result<&'a [Value], String> {
    value
        .get(key)
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .ok_or_else(|| format!("{key} must be an array"))
}

fn checked_object<'a>(
    value: &'a Value,
    key: &str,
) -> Result<&'a serde_json::Map<String, Value>, String> {
    value
        .get(key)
        .and_then(Value::as_object)
        .ok_or_else(|| format!("{key} must be an object"))
}

fn checked_text<'a>(value: &'a Value, key: &str) -> Result<&'a str, String> {
    value
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("{key} must be a string"))
}

fn checked_string_set(value: &Value, key: &str) -> Result<BTreeSet<String>, String> {
    checked_array(value, key)?
        .iter()
        .map(|entry| {
            entry
                .as_str()
                .map(str::to_owned)
                .ok_or_else(|| format!("{key} entries must be strings"))
        })
        .collect()
}

fn checked_json_sha256(value: &Value) -> Result<String, String> {
    let bytes = serde_json::to_vec(value)
        .map_err(|error| format!("failed to serialize JSON for exact comparison: {error}"))?;
    Ok(hex::encode(Sha256::digest(bytes)))
}

fn validate_inventory(inventory: &Value) -> Result<(), String> {
    if inventory.get("schema_version").and_then(Value::as_u64) != Some(1) {
        return Err("schema_version must be 1".to_owned());
    }
    for (key, expected) in [
        ("artifact_id", "regex-privacy-capability-inventory-v1"),
        ("program_id", PROGRAM_ID),
        ("bead_id", BEAD_ID),
        ("capability_id", CAPABILITY_ID),
        ("baseline_revision", BASELINE_REVISION),
        ("authority_revision", AUTHORITY_REVISION),
    ] {
        if inventory.get(key).and_then(Value::as_str) != Some(expected) {
            return Err(format!("{key} must be {expected}"));
        }
    }

    let authority = object(inventory, "authority");
    for (key, expected) in [
        ("adr_id", ADR_ID),
        ("decision", "KEEP_UNTIL_PARITY"),
        ("disposition", "KEEP_INCUMBENT"),
        ("cutover_state", "BLOCKED_PENDING_FULL_PARITY"),
    ] {
        if authority.get(key).and_then(Value::as_str) != Some(expected) {
            return Err(format!("authority.{key} must be {expected}"));
        }
    }
    if authority
        .get("dependency_exit_allowed")
        .and_then(Value::as_bool)
        != Some(false)
        || authority
            .get("fixed_scanners_are_general_replacement")
            .and_then(Value::as_bool)
            != Some(false)
    {
        return Err("authority must forbid dependency exit and scanner overclaim".to_owned());
    }

    let policy = object(inventory, "policy");
    if policy.get("zero_unknown_required").and_then(Value::as_bool) != Some(true)
        || policy.get("unknown_rows").and_then(Value::as_u64) != Some(0)
        || policy.get("inventory_state").and_then(Value::as_str)
            != Some("BASELINED_WITH_ROUTED_GAPS")
        || policy.get("evidence_state").and_then(Value::as_str)
            != Some("EXECUTABLE_PARTIAL_BLOCKING")
    {
        return Err(
            "policy must remain executable-partial, fail-closed, and zero-unknown".to_owned(),
        );
    }
    let accepted_states = checked_string_set(
        inventory
            .get("policy")
            .ok_or_else(|| "policy is required".to_owned())?,
        "accepted_states",
    )?;
    let expected_accepted_states: BTreeSet<String> = [
        "BASELINED",
        "PRESENT",
        "ABSENT",
        "PLANNED",
        "BLOCKED",
        "ROUTED",
        "RESOLVED",
        "RESOLVED_BEFORE_BASELINE",
        "OUT_OF_SCOPE",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect();
    if accepted_states != expected_accepted_states {
        return Err("policy.accepted_states drifted".to_owned());
    }
    validate_no_unknown(inventory, "$")?;

    let expected_surfaces: BTreeSet<String> = [
        "RGX-PUB-CONFIG",
        "RGX-PUB-BUILDERS",
        "RGX-PUB-MATCH",
        "RGX-PUB-SPAN-ALIAS",
        "RGX-PUB-LOG-PRIVACY",
        "RGX-TEST-METRICS-PRIVACY",
        "RGX-TEST-TRACE-PRIVACY",
        "RGX-TEST-LOG-WIRE-PRIVACY",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect();
    if row_ids(array(inventory, "public_surface"), "surface_id") != expected_surfaces {
        return Err("public and signal surface inventory drifted".to_owned());
    }

    for (key, count, id_key) in [
        ("syntax_corpus", 31, "case_id"),
        ("field_policy_corpus", 11, "case_id"),
        ("built_in_detector_corpus", 11, "case_id"),
        ("resource_and_concurrency_corpus", 6, "case_id"),
        ("migration_reservation_groups", 5, "group_id"),
        ("gaps", 14, "gap_id"),
    ] {
        let rows = array(inventory, key);
        if rows.len() != count || row_ids(rows, id_key).len() != count {
            return Err(format!("{key} must contain {count} unique rows"));
        }
    }

    let expected_syntax_classes: BTreeSet<String> = [
        "literal-and-counted-repetition",
        "alternation-left-branch",
        "named-capture",
        "absolute-anchors",
        "multiline-anchors",
        "dotall",
        "crlf-mode",
        "unicode-case-fold",
        "unicode-script",
        "class-intersection-subtraction",
        "class-symmetric-difference",
        "empty-pattern",
        "zero-width-anchor",
        "nested-repetition-linear-engine",
        "lookahead-unsupported",
        "backreference-unsupported",
        "invalid-repetition-range",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect();
    let actual_syntax_classes: BTreeSet<String> = array(inventory, "syntax_corpus")
        .iter()
        .map(|row| text(row, "class").to_owned())
        .collect();
    if !expected_syntax_classes.is_subset(&actual_syntax_classes) {
        return Err("syntax corpus is missing a required semantic class".to_owned());
    }

    let gaps = array(inventory, "gaps");
    let expected_gaps: BTreeSet<String> = (1..=14)
        .map(|suffix| format!("RGX-R1-GAP-{suffix:02}"))
        .collect();
    if row_ids(gaps, "gap_id") != expected_gaps {
        return Err("gap inventory must retain the exact RGX-R1-GAP-01..14 set".to_owned());
    }
    for gap in gaps {
        if text(gap, "owner").is_empty()
            || !accepted_states.contains(text(gap, "state"))
            || !matches!(
                text(gap, "state"),
                "ROUTED" | "RESOLVED" | "RESOLVED_BEFORE_BASELINE"
            )
        {
            return Err(format!(
                "{} must be routed or explicitly resolved",
                text(gap, "gap_id")
            ));
        }
    }

    let downstream = inventory
        .get("downstream_and_e2e")
        .ok_or_else(|| "downstream_and_e2e is required".to_owned())?;
    let scenarios = array(downstream, "planned_scenarios");
    let expected_scenarios: BTreeSet<String> = [
        "regex_custom_patterns",
        "privacy_multisignal_redaction",
        "regex_adversarial_limits",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect();
    if row_ids(scenarios, "scenario_id") != expected_scenarios
        || scenarios
            .iter()
            .any(|row| text(row, "state") != "PLANNED" || text(row, "owner").is_empty())
    {
        return Err("all three canonical scenarios must remain planned and owned".to_owned());
    }

    if array(inventory, "rollback_triggers").len() != 9
        || array(inventory, "no_claim_boundaries").len() != 8
    {
        return Err("rollback and no-claim boundaries must remain complete".to_owned());
    }
    Ok(())
}

#[test]
fn inventory_is_complete_source_pinned_and_zero_unknown() {
    let inventory = artifact();
    validate_inventory(&inventory).unwrap_or_else(|error| panic!("{error}"));

    for pin in array(&inventory, "source_pins") {
        let path = text(pin, "path");
        let bytes = read_repo_bytes(path);
        let digest = hex::encode(Sha256::digest(&bytes));
        assert_eq!(digest, text(pin, "sha256"), "{path} source pin drifted");
        assert_eq!(
            pin.get("line_count").and_then(Value::as_u64),
            Some(read_repo_file(path).lines().count() as u64),
            "{path} line count drifted"
        );
    }
}

#[test]
fn authority_registry_baseline_and_source_routes_are_truthful() {
    let adr = read_repo_file(ADR_PATH);
    for marker in [
        ADR_ID,
        CAPABILITY_ID,
        "KEEP_UNTIL_PARITY",
        "KEEP_INCUMBENT",
        "Fixed scanners are not a general regex engine",
        "src/observability/otel.rs",
    ] {
        assert!(adr.contains(marker), "ADR must retain {marker}");
    }

    let registry = parse_repo_json(CAPABILITY_REGISTRY_PATH);
    let capability = find_row(
        array(&registry, "capabilities"),
        "capability_id",
        CAPABILITY_ID,
    );
    assert_eq!(
        capability.get("disposition").and_then(Value::as_str),
        Some("KEEP_UNTIL_PARITY")
    );
    assert_eq!(
        capability.get("cutover_state").and_then(Value::as_str),
        Some("KEEP_INCUMBENT")
    );
    assert_eq!(
        string_set(capability, "source_owners"),
        ["Cargo.toml", "src/observability/otel.rs"]
            .into_iter()
            .map(str::to_owned)
            .collect()
    );
    assert!(
        string_set(capability, "security_invariants")
            .contains("custom privacy patterns never silently ignored")
    );

    let baseline = parse_repo_json(BASELINE_PATH);
    let baseline_row = find_row(
        array(&baseline, "capability_baselines"),
        "capability_id",
        CAPABILITY_ID,
    );
    assert_eq!(
        baseline_row.get("baseline_state").and_then(Value::as_str),
        Some("EXECUTABLE_PARTIAL_BLOCKING")
    );
    assert_eq!(
        baseline_row
            .get("cutover_eligible")
            .and_then(Value::as_bool),
        Some(false)
    );
    assert_eq!(
        text(
            baseline_row
                .get("cases")
                .and_then(Value::as_object)
                .and_then(|cases| cases.get("malformed_error"))
                .expect("malformed error row"),
            "disposition"
        ),
        "BLOCKED_OWNER"
    );

    let manifest = read_repo_file("Cargo.toml");
    let lockfile = read_repo_file("Cargo.lock");
    let source = read_repo_file("src/observability/otel.rs");
    let facade = read_repo_file("src/observability/mod.rs");
    let api_map = read_repo_file(API_SURFACE_MAP_PATH);
    assert!(manifest.contains("regex = { version = \"1.12\", optional = true }"));
    assert!(manifest.contains("\"dep:regex\""));
    assert!(lockfile.contains("name = \"regex\"\nversion = \"1.13.1\""));
    assert!(source.contains("pub struct PrivacyConfig"));
    assert!(source.contains("pub type SpanConfig = PrivacyConfig;"));
    assert!(source.contains("Err(_) => return true"));
    assert!(source.contains("allowing a value through under an invalid privacy policy"));
    assert!(source.contains("fn apply_auto_pii_redaction"));
    assert!(!facade.contains("pub use otel::PrivacyConfig"));
    assert!(!api_map.contains("\"PrivacyConfig\""));
}

#[test]
fn occurrence_census_separates_real_dependency_mock_and_literal() {
    let inventory = artifact();
    let census = object(&inventory, "occurrence_census");
    assert_eq!(
        census.get("unknown_occurrences").and_then(Value::as_u64),
        Some(0)
    );

    let otel = read_repo_file("src/observability/otel.rs");
    let fixture =
        read_repo_file("tests/fixtures/dependency-capability-baseline-consumer/src/lib.rs");
    let former_mock = read_repo_file("src/net/atp/chunk/artifact.rs");
    let audit = read_repo_file("tests/otel_metric_attribute_denylist_audit.rs");
    assert_eq!(otel.matches("PrivacyConfig").count(), 32);
    assert_eq!(fixture.matches("PrivacyConfig").count(), 2);
    assert_eq!(otel.matches("SpanConfig").count(), 6);
    assert_eq!(otel.matches("regex::").count(), 2);
    assert_eq!(former_mock.matches("regex::").count(), 0);
    assert_eq!(audit.matches("regex::").count(), 1);
    assert_eq!(otel.matches("Regex").count(), 20);
    assert_eq!(former_mock.matches("Regex").count(), 0);
    assert!(!former_mock.contains("mod regex"));
    assert!(!former_mock.contains("pub struct Regex"));
}

#[test]
fn full_syntax_corpus_matches_incumbent_compile_match_and_privacy_behavior() {
    let inventory = artifact();
    for row in array(&inventory, "syntax_corpus") {
        let case_id = text(row, "case_id");
        let pattern = text(row, "pattern");
        match text(row, "compile_state") {
            "ACCEPTED" => {
                let compiled = IncumbentRegex::new(pattern)
                    .unwrap_or_else(|error| panic!("{case_id} unexpectedly rejected: {error}"));
                let haystack = text(row, "haystack");
                let expected_match = row
                    .get("matches")
                    .and_then(Value::as_bool)
                    .expect("accepted syntax case must name matches");
                assert_eq!(
                    compiled.is_match(haystack),
                    expected_match,
                    "{case_id} incumbent match drifted"
                );

                let config = PrivacyConfig::new()
                    .try_with_pii_pattern(pattern)
                    .unwrap_or_else(|error| panic!("{case_id} builder rejected: {error}"));
                assert_eq!(
                    config.redact_pii("inventory.value", haystack),
                    if expected_match {
                        "[REDACTED]".to_owned()
                    } else {
                        haystack.to_owned()
                    },
                    "{case_id} PrivacyConfig behavior drifted"
                );
            }
            "REJECTED" => {
                let error = IncumbentRegex::new(pattern)
                    .unwrap_err_or_else(|| panic!("{case_id} unexpectedly compiled"))
                    .to_string();
                assert!(
                    error.contains(text(row, "error_contains")),
                    "{case_id} error `{error}` lost expected fragment `{}`",
                    text(row, "error_contains")
                );
                assert!(
                    PrivacyConfig::new().try_with_pii_pattern(pattern).is_err(),
                    "{case_id} public fallible builder unexpectedly accepted"
                );
            }
            state => panic!("{case_id} has unsupported compile_state {state}"),
        }
    }
}

trait ResultExt<T, E> {
    fn unwrap_err_or_else(self, fallback: impl FnOnce() -> E) -> E;
}

impl<T, E> ResultExt<T, E> for Result<T, E> {
    fn unwrap_err_or_else(self, fallback: impl FnOnce() -> E) -> E {
        match self {
            Ok(_) => fallback(),
            Err(error) => error,
        }
    }
}

#[test]
fn field_policy_corpus_preserves_precedence_glob_and_case_behavior() {
    let inventory = artifact();
    for row in array(&inventory, "field_policy_corpus") {
        let mut config = PrivacyConfig::new();
        config.drop_attributes = array(row, "drop_attributes")
            .iter()
            .map(|entry| entry.as_str().expect("drop attribute").to_owned())
            .collect();
        config.drop_labels = array(row, "drop_labels")
            .iter()
            .map(|entry| entry.as_str().expect("drop label").to_owned())
            .collect();
        config.allowed_fields = array(row, "allowed_fields")
            .iter()
            .map(|entry| entry.as_str().expect("allowed field").to_owned())
            .collect();
        assert_eq!(
            config.should_drop_field(text(row, "field")),
            row.get("drop")
                .and_then(Value::as_bool)
                .expect("field row drop"),
            "{} field policy drifted",
            text(row, "case_id")
        );
    }

    let merged = PrivacyConfig::new().with_drop_label("span.secret");
    assert!(
        merged.should_drop_field("span.secret"),
        "drop_labels must remain signal-merged into the shared predicate"
    );
    let star = PrivacyConfig::new().with_allowed_field("*");
    assert!(!star.should_drop_field("a.b.c"));
    assert!(!star.should_drop_field(""));
}

#[test]
fn built_in_detector_corpus_preserves_order_luhn_and_whole_value_tokens() {
    let inventory = artifact();
    for row in array(&inventory, "built_in_detector_corpus") {
        let mut config = PrivacyConfig::new().with_auto_pii_detection();
        if let Some(pattern) = row.get("custom_pattern").and_then(Value::as_str) {
            config = config
                .try_with_pii_pattern(pattern)
                .expect("corpus custom pattern must compile");
        }
        assert_eq!(
            config.redact_pii("inventory.value", text(row, "value")),
            text(row, "output"),
            "{} built-in detector drifted",
            text(row, "case_id")
        );
    }

    let field_ignored = PrivacyConfig::new()
        .try_with_pii_pattern("secret")
        .expect("valid pattern");
    assert_eq!(
        field_ignored.redact_pii("public", "secret"),
        field_ignored.redact_pii("private", "secret")
    );
}

fn panic_text(payload: Box<dyn std::any::Any + Send>) -> String {
    if let Some(message) = payload.downcast_ref::<String>() {
        return message.clone();
    }
    if let Some(message) = payload.downcast_ref::<&str>() {
        return (*message).to_owned();
    }
    "<non-string panic>".to_owned()
}

#[test]
fn mutation_error_panic_and_diagnostic_exposure_remain_explicit() {
    let inventory = artifact();
    let invalid_mutation_row = find_row(
        array(&inventory, "resource_and_concurrency_corpus"),
        "case_id",
        "RGX-RES-006",
    );
    assert_eq!(text(invalid_mutation_row, "state"), "RESOLVED");
    assert_eq!(
        text(invalid_mutation_row, "expected"),
        "invalid direct entry fails closed to whole-value redaction even when the compiled cache is populated or stale"
    );

    let mut valid_mutation = PrivacyConfig::new();
    valid_mutation.pii_patterns.push("secret-[0-9]+".to_owned());
    assert_eq!(valid_mutation.redact_pii("auth", "secret-42"), "[REDACTED]");

    let mut invalid_mutation = PrivacyConfig::new();
    invalid_mutation.pii_patterns.push("(".to_owned());
    assert_eq!(
        invalid_mutation.redact_pii("auth", "secret-42"),
        "[REDACTED]",
        "RGX-R1-GAP-01: invalid direct mutation must fail closed"
    );

    let mut mixed_mutation = PrivacyConfig::new();
    mixed_mutation.pii_patterns.push("public-[0-9]+".to_owned());
    mixed_mutation.pii_patterns.push("[invalid".to_owned());
    assert_eq!(
        mixed_mutation.redact_pii("auth", "unmatched-secret"),
        "[REDACTED]",
        "one invalid direct entry must fail the entire privacy policy closed"
    );

    let mut cached_length_mismatch = PrivacyConfig::new()
        .try_with_pii_pattern("public-[0-9]+")
        .expect("valid cached pattern");
    cached_length_mismatch.pii_patterns.push("(".to_owned());
    assert_eq!(
        cached_length_mismatch.redact_pii("auth", "unmatched-secret"),
        "[REDACTED]",
        "an invalid direct append must fail closed when the compiled cache was populated"
    );

    let mut cached_content_mismatch = PrivacyConfig::new()
        .try_with_pii_pattern("public-[0-9]+")
        .expect("valid cached pattern");
    cached_content_mismatch.pii_patterns[0] = "(".to_owned();
    assert_eq!(
        cached_content_mismatch.redact_pii("auth", "unmatched-secret"),
        "[REDACTED]",
        "an invalid in-place replacement must fail closed when cache length still matches"
    );

    let canary = "TOP-SECRET-CANARY-[";
    let error = PrivacyConfig::new()
        .try_with_pii_pattern(canary)
        .expect_err("invalid canary pattern")
        .to_string();
    assert!(
        error.contains(canary),
        "fallible diagnostic exposure must remain explicitly inventoried"
    );

    let debug_canary = "PRIVATE-CANARY-[0-9]+";
    let config = PrivacyConfig::new()
        .try_with_pii_pattern(debug_canary)
        .expect("valid debug canary");
    assert!(format!("{config:?}").contains(debug_canary));

    let panic = std::panic::catch_unwind(|| PrivacyConfig::new().with_pii_pattern("("))
        .expect_err("infallible builder must panic");
    assert!(
        panic_text(panic).contains("invalid PrivacyConfig PII regex pattern"),
        "panic context drifted"
    );
}

fn assert_send_sync<T: Send + Sync>() {}

#[test]
fn bounded_resource_and_concurrency_probes_match_the_baseline() {
    assert_send_sync::<PrivacyConfig>();

    let config = Arc::new(
        PrivacyConfig::new()
            .try_with_pii_pattern("secret-[0-9]+")
            .expect("valid shared pattern"),
    );
    std::thread::scope(|scope| {
        let mut joins = Vec::new();
        for _ in 0..8 {
            let config = Arc::clone(&config);
            joins.push(scope.spawn(move || config.redact_pii("auth", "prefix secret-42 suffix")));
        }
        for join in joins {
            assert_eq!(join.join().expect("thread must join"), "[REDACTED]");
        }
    });

    let large = format!("{}!", "a".repeat(65_536));
    let nested = IncumbentRegex::new("(a+)+$").expect("nested repetition compiles");
    assert!(!nested.is_match(&large));

    let deeply_nested = format!("{}a{}", "(".repeat(251), ")".repeat(251));
    let nest_error = IncumbentRegex::new(&deeply_nested)
        .expect_err("251 nested captures must exceed the default syntax limit")
        .to_string();
    let nest_error = nest_error.to_ascii_lowercase();
    assert!(
        nest_error.contains("maximum number of nested parentheses/brackets (250)"),
        "unexpected nesting error: {nest_error}"
    );

    let size_error = IncumbentRegex::new("(?:a){1000000}")
        .expect_err("expanded repetition must exceed the default compiled size limit")
        .to_string();
    let size_error = size_error.to_ascii_lowercase();
    assert!(
        size_error.contains("compiled regex exceeds size limit of 10485760 bytes"),
        "unexpected compiled-size error: {size_error}"
    );
}

#[test]
fn log_privacy_filters_attributes_but_not_body_and_source_gates_remain_visible() {
    let privacy = PrivacyConfig::new()
        .with_drop_attribute("drop.me")
        .try_with_pii_pattern("secret-[0-9]+")
        .expect("valid custom pattern");
    let record = OtlpLogRecord::new(LogLevel::Info, "body secret-42", 1)
        .with_filtered_attribute("drop.me", "secret-1", &privacy)
        .with_filtered_attribute("keep.me", "secret-42", &privacy);
    assert_eq!(record.body, "body secret-42");
    assert_eq!(
        record.attributes,
        vec![("keep.me".to_owned(), "[REDACTED]".to_owned())]
    );
    assert_eq!(record.dropped_attributes_count, 1);

    let _: SpanConfig = privacy.clone();
    let source = read_repo_file("src/observability/otel.rs");
    assert!(source.contains("#[cfg(all("));
    assert!(source.contains("any(test, feature = \"fuzz\")"));
    assert!(source.contains("pub fn metrics_request_from_snapshot_with_privacy"));
    assert!(source.contains("fn proto_span(span: &TestSpan) -> ProtoSpan"));
    assert!(source.contains("ordered_proto_attributes(&span.attributes)"));
    assert!(source.contains("body: Some(string_value(&record.body))"));
}

#[test]
fn marginal_graph_downstream_routing_docs_and_no_claims_are_exact() {
    let inventory = artifact();
    let marginal = object(&inventory, "marginal_counterfactual");
    assert_eq!(marginal.get("cells").and_then(Value::as_u64), Some(8));
    assert_eq!(
        marginal
            .get("metrics_marginal_package_count")
            .and_then(Value::as_u64),
        Some(3)
    );
    assert_eq!(
        marginal
            .get("workspace_dev_build_audit_marginal_package_count")
            .and_then(Value::as_u64),
        Some(0)
    );
    for key in ["build_scripts", "proc_macros", "native_code"] {
        assert!(
            marginal
                .get(key)
                .and_then(Value::as_array)
                .expect("marginal list")
                .is_empty(),
            "{key} must remain empty"
        );
    }

    let ledger = parse_repo_json(MARGINAL_LEDGER_PATH);
    let cells: Vec<&Value> = array(&ledger, "marginal_measurements")
        .iter()
        .filter(|row| row.get("direct_root_edge").and_then(Value::as_str) == Some("normal:regex"))
        .collect();
    assert_eq!(cells.len(), 8);
    let metrics: Vec<&&Value> = cells
        .iter()
        .filter(|row| row.get("feature_profile").and_then(Value::as_str) == Some("metrics"))
        .collect();
    let workspace: Vec<&&Value> = cells
        .iter()
        .filter(|row| {
            row.get("feature_profile").and_then(Value::as_str) == Some("workspace-dev-build-audit")
        })
        .collect();
    assert_eq!(metrics.len(), 4);
    assert_eq!(workspace.len(), 4);
    for row in metrics {
        assert_eq!(
            row.get("marginal_package_version_count")
                .and_then(Value::as_u64),
            Some(3)
        );
        assert!(array(row, "build_scripts").is_empty());
        assert!(array(row, "proc_macros").is_empty());
    }
    for row in workspace {
        assert_eq!(
            row.get("marginal_package_version_count")
                .and_then(Value::as_u64),
            Some(0)
        );
    }

    let downstream = inventory
        .get("downstream_and_e2e")
        .expect("downstream inventory");
    assert_eq!(
        downstream
            .get("canonical_runner_rows_present")
            .and_then(Value::as_u64),
        Some(0)
    );
    let fixture = downstream
        .get("existing_downstream_fixture")
        .expect("fixture row");
    assert_eq!(array(fixture, "proves").len(), 4);
    assert_eq!(array(fixture, "does_not_prove").len(), 8);

    let doc = read_repo_file(DOC_PATH);
    let begin = doc.find(DOC_BEGIN).expect("doc begin marker");
    let end = doc.find(DOC_END).expect("doc end marker");
    assert!(begin < end);
    for marker in [
        "`CAP-REGEX-PRIVACY`",
        "`KEEP_UNTIL_PARITY` / `KEEP_INCUMBENT`",
        "`RGX-R1-GAP-01`",
        "`RGX-R1-GAP-05`",
        "`regex_custom_patterns`",
        "`privacy_multisignal_redaction`",
        "`regex_adversarial_limits`",
        "zero `UNKNOWN`",
        "No local Cargo fallback",
    ] {
        assert!(doc.contains(marker), "documentation must retain {marker}");
    }
}

#[test]
fn r3_5_4_private_api_compatibility_extension_is_complete_and_source_pinned() {
    let map = parse_repo_json(PRIVATE_API_MAP_PATH);
    let extension = map
        .get("r3_5_4_compatibility_extension")
        .expect("R3.5.4 compatibility extension");
    for (key, expected) in [
        ("extension_id", "ASUP-REGEX-PRIVATE-API-COMPATIBILITY-V1"),
        ("bead_id", "asupersync-5z2scg.8.3.5.4"),
        ("claim_revision", "da992970cbb0590014a36236682c138cd83b41a4"),
    ] {
        assert_eq!(
            extension.get(key).and_then(Value::as_str),
            Some(expected),
            "R3.5.4 {key} drifted"
        );
    }
    assert_eq!(
        extension
            .get("historical_r3_5_1_base_preserved")
            .and_then(Value::as_bool),
        Some(true)
    );
    validate_no_unknown(
        extension
            .get("capability_rows")
            .expect("R3.5.4 capability rows"),
        "$.r3_5_4_compatibility_extension.capability_rows",
    )
    .expect("R3.5.4 extension must contain no UNKNOWN row");

    for pin in array(extension, "source_pins") {
        let path = text(pin, "path");
        assert!(
            repo_root().join(path).is_file(),
            "missing historical source {path}"
        );
        assert_eq!(
            text(pin, "sha256").len(),
            64,
            "invalid historical hash for {path}"
        );
        assert!(
            pin.get("line_count")
                .and_then(Value::as_u64)
                .is_some_and(|count| count > 0),
            "invalid historical line count for {path}"
        );
        assert_eq!(
            pin.get("revision").and_then(Value::as_str),
            Some("da992970cbb0590014a36236682c138cd83b41a4")
        );
    }
    assert_eq!(array(extension, "source_pins").len(), 7);

    let rows = array(extension, "capability_rows");
    let expected_ids: BTreeSet<String> = [
        "RGX-R354-COMPILE",
        "RGX-R354-VALIDATION",
        "RGX-R354-MATCH",
        "RGX-R354-FIND",
        "RGX-R354-CAPTURES",
        "RGX-R354-ITERATION",
        "RGX-R354-REPLACEMENT",
        "RGX-R354-DIAGNOSTICS",
        "RGX-R354-LIMITS",
        "RGX-R354-CONFIGURATION",
        "RGX-R354-PUB-NESTED-PATH",
        "RGX-R354-PUB-SPAN-ALIAS",
        "RGX-R354-PUB-MUTABLE-FIELDS",
        "RGX-R354-PUB-DIRECT-MUTATION",
        "RGX-R354-PUB-FALLIBLE-BUILDER",
        "RGX-R354-PUB-PANIC-BUILDER",
        "RGX-R354-PUB-CLONE-DEBUG",
        "RGX-R354-PUB-FEATURE-GATE",
        "RGX-R354-CANDIDATE-VISIBILITY",
        "RGX-R354-BYTE-REGEX",
        "RGX-R354-BUILTIN-ORDER-LUHN",
        "RGX-R354-PRODUCTION-WIRING",
        "RGX-R354-WHOLE-OP-CANCELLATION",
        "RGX-R354-STRICT-REPLACEMENT",
        "RGX-R354-CROSS-TARGET-CONFIG",
        "RGX-R354-PUBLIC-SERIALIZATION",
        "RGX-R354-GAP-NULLABLE-LOOP",
        "RGX-R354-GAP-ZERO-COUNT-CAPTURE",
        "RGX-R354-GAP-DOTTED-AGE",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect();
    assert_eq!(row_ids(rows, "surface_id"), expected_ids);

    let same_ids: BTreeSet<&str> = [
        "RGX-R354-COMPILE",
        "RGX-R354-VALIDATION",
        "RGX-R354-MATCH",
        "RGX-R354-FIND",
        "RGX-R354-CAPTURES",
        "RGX-R354-ITERATION",
        "RGX-R354-REPLACEMENT",
    ]
    .into_iter()
    .collect();
    for row in rows {
        let surface_id = text(row, "surface_id");
        assert_eq!(
            text(row, "disposition"),
            if same_ids.contains(surface_id) {
                "SAME"
            } else {
                "KEEP"
            },
            "{surface_id} must remain explicitly SAME or KEEP"
        );
        assert!(!text(row, "evidence").is_empty());
    }

    let decision = object(extension, "decision");
    assert_eq!(
        decision.get("disposition").and_then(Value::as_str),
        Some("KEEP_INCUMBENT")
    );
    assert_eq!(
        decision.get("unknown_rows").and_then(Value::as_u64),
        Some(0)
    );
    for forbidden in [
        "public_reexport_authorized",
        "privacy_config_integration_authorized",
        "compatibility_shim_authorized",
        "production_wiring_authorized",
        "dependency_removal_authorized",
    ] {
        assert_eq!(
            decision.get(forbidden).and_then(Value::as_bool),
            Some(false),
            "R3.5.4 must not authorize {forbidden}"
        );
    }

    let config = object(extension, "configuration_contract");
    assert_eq!(
        config.get("schema_version").and_then(Value::as_u64),
        Some(1)
    );
    assert_eq!(
        config
            .get("default_document_byte_ceiling")
            .and_then(Value::as_u64),
        Some(8 * 1024 * 1024)
    );
    for key in [
        "load_is_atomic",
        "serializer_is_structural_not_admission",
        "serializer_never_returns_a_document_above_its_selected_ceiling",
        "explicit_config_retains_pattern",
        "loaded_value_is_send_sync",
        "replacement_zero_limits_are_valid_when_the_operation_uses_zero",
    ] {
        assert_eq!(
            config.get(key).and_then(Value::as_bool),
            Some(true),
            "configuration contract lost {key}"
        );
    }
    assert_eq!(
        config
            .get("loaded_value_retains_pattern")
            .and_then(Value::as_bool),
        Some(false)
    );
    assert_eq!(
        config
            .get("cross_target_oversized_integer_disposition")
            .and_then(Value::as_str),
        Some("KEEP")
    );

    let evidence = array(extension, "executable_evidence");
    assert_eq!(evidence.len(), 4);
    for row in evidence {
        assert!(text(row, "result").starts_with("PASS"));
        assert_eq!(
            row.get("remote_required").and_then(Value::as_bool),
            Some(true)
        );
        assert_eq!(
            row.get("local_fallback_used").and_then(Value::as_bool),
            Some(false)
        );
    }

    let facade = read_repo_file("src/observability/mod.rs");
    assert!(facade.contains("pub(crate) mod regex_vm;"));
    assert!(!facade.contains("pub mod regex_vm;"));
    let downstream =
        read_repo_file("tests/fixtures/downstream-consumer-proof/src/bin/metrics_consumer.rs");
    assert!(downstream.contains("asupersync::observability::otel::PrivacyConfig"));
    assert!(!downstream.contains("PrivatePatternConfig"));

    let doc = read_repo_file("docs/regex_private_compile_api_map.md");
    for marker in [
        "R3.5.4 compatibility extension",
        "ASUP-REGEX-PRIVATE-API-COMPATIBILITY-V1",
        "da992970cbb0590014a36236682c138cd83b41a4",
        "target-local `KEEP`",
        "KEEP_INCUMBENT",
        "metrics_consumer.rs",
        "30 of 30 tests passed",
    ] {
        assert!(
            doc.contains(marker),
            "R3.5.4 documentation must retain {marker}"
        );
    }
}

fn validate_r3_5_5_terminal(map: &Value, inventory: &Value) -> Result<(), String> {
    let receipt = map
        .get("r3_5_5_terminal_receipt")
        .ok_or_else(|| "r3_5_5_terminal_receipt is required".to_owned())?;
    validate_no_unknown(receipt, "$.r3_5_5_terminal_receipt")?;

    for (key, expected) in [
        ("receipt_id", "ASUP-REGEX-R3-5-PRIVATE-API-TERMINAL-V1"),
        ("bead_id", "asupersync-5z2scg.8.3.5.5"),
        (
            "evidence_base_revision",
            "903de8267e50fc5ba5652766157bd2083aee6e4c",
        ),
        ("captured_at_utc", "2026-08-21T12:34:19Z"),
    ] {
        if checked_text(receipt, key)? != expected {
            return Err(format!("R3.5.5 {key} drifted"));
        }
    }

    let repair = checked_object(receipt, "security_repair")?;
    for (key, expected) in [
        ("gap_id", "RGX-R1-GAP-01"),
        (
            "source_revision",
            "903de8267e50fc5ba5652766157bd2083aee6e4c",
        ),
        ("source_path", "src/observability/otel.rs"),
        (
            "regression_test",
            "mutation_error_panic_and_diagnostic_exposure_remain_explicit",
        ),
    ] {
        if repair.get(key).and_then(Value::as_str) != Some(expected) {
            return Err(format!("security repair {key} drifted"));
        }
    }
    if repair.get("public_api_changed").and_then(Value::as_bool) != Some(false) {
        return Err("RGX-R1-GAP-01 repair must not change the public API".to_owned());
    }
    let repair_path = repair
        .get("source_path")
        .and_then(Value::as_str)
        .ok_or_else(|| "security repair source_path is required".to_owned())?;
    if repair.get("source_sha256").and_then(Value::as_str)
        != Some("b036610d07e07b7a7e9ed3e23328d60104f2429cbe464827213a8bff5f7e0db8")
        || repair.get("source_line_count").and_then(Value::as_u64) != Some(14_533)
    {
        return Err("RGX-R1-GAP-01 historical source pin drifted".to_owned());
    }
    let live_repair_source = read_repo_file(repair_path);
    for marker in [
        "Err(_) => return true",
        "allowing a value through under an invalid privacy policy",
    ] {
        if !live_repair_source.contains(marker) {
            return Err(format!("RGX-R1-GAP-01 live repair lost {marker}"));
        }
    }

    let decision = checked_object(receipt, "decision")?;
    if decision.get("disposition").and_then(Value::as_str) != Some("KEEP_INCUMBENT_DEFER")
        || decision
            .get("r3_5_private_api_complete")
            .and_then(Value::as_bool)
            != Some(true)
        || decision
            .get("r3_7_1_independent_corpus_may_proceed")
            .and_then(Value::as_bool)
            != Some(true)
        || decision
            .get("r3_7_terminal_decision_ready")
            .and_then(Value::as_bool)
            != Some(false)
        || decision
            .get("r3_6_cache_performance_policy_remains_required")
            .and_then(Value::as_bool)
            != Some(true)
        || decision
            .get("unresolved_high_findings_complete")
            .and_then(Value::as_bool)
            != Some(true)
        || decision.get("unknown_rows").and_then(Value::as_u64) != Some(0)
    {
        return Err("R3.5.5 decision must remain fail-closed and R3.7-bounded".to_owned());
    }
    for forbidden in [
        "public_reexport_authorized",
        "privacy_config_integration_authorized",
        "compatibility_shim_authorized",
        "production_wiring_authorized",
        "dependency_removal_authorized",
    ] {
        if decision.get(forbidden).and_then(Value::as_bool) != Some(false) {
            return Err(format!("R3.5.5 must not authorize {forbidden}"));
        }
    }

    let expected_high_gaps: BTreeSet<String> = checked_array(inventory, "gaps")?
        .iter()
        .filter(|row| {
            row.get("state").and_then(Value::as_str) == Some("ROUTED")
                && matches!(
                    row.get("severity").and_then(Value::as_str),
                    Some("critical" | "high")
                )
        })
        .map(|row| checked_text(row, "gap_id").map(str::to_owned))
        .collect::<Result<_, _>>()?;
    if expected_high_gaps.len() != 7 {
        return Err(
            "pinned inventory must expose exactly seven routed critical/high gaps".to_owned(),
        );
    }
    if checked_string_set(
        receipt.get("decision").expect("decision"),
        "unresolved_critical_or_high_gap_ids",
    )? != expected_high_gaps
    {
        return Err("R3.5.5 must enumerate every routed critical/high gap".to_owned());
    }

    let expected_predecessors = [
        (
            "artifacts/regex_privacy_capability_inventory_v1.json",
            "2f0264e45f9362d4b299c235f82b415d553b8f6fd40a05aef25f84c948f75a5e",
            1015,
        ),
        (
            "artifacts/regex_syntax_terminal_receipt_v1.json",
            "410afeaeb0250a36b8d91c1a78b612c942d729fd495e7752c3f5965bbe8d5fbe",
            391,
        ),
        (
            "artifacts/regex_semantic_terminal_receipt_v1.json",
            "42d00d7c92b2b4a9974c252481432142eae2927b9442ffe08265769e00f7c8a2",
            433,
        ),
        (
            "artifacts/regex_compiler_terminal_receipt_v1.json",
            "3a67d943175079ab0378080de5b8ee06fd5e979b0c9555dc30a45cbb62da2f5b",
            252,
        ),
        (
            "artifacts/regex_vm_terminal_receipt_v1.json",
            "608b42b5bedeed536884af10b325fff889668e5819a6cdf6d85afcf9debc2265",
            337,
        ),
    ];
    let predecessors = checked_array(receipt, "predecessor_receipts")?;
    if predecessors.len() != expected_predecessors.len() {
        return Err("R3.5.5 predecessor receipt count drifted".to_owned());
    }
    for (path, digest, line_count) in expected_predecessors {
        let pin = predecessors
            .iter()
            .find(|row| row.get("path").and_then(Value::as_str) == Some(path))
            .ok_or_else(|| format!("missing predecessor {path}"))?;
        if pin.get("sha256").and_then(Value::as_str) != Some(digest)
            || pin.get("line_count").and_then(Value::as_u64) != Some(line_count)
            || !repo_root().join(path).is_file()
        {
            return Err(format!("predecessor pin drifted for {path}"));
        }
    }

    let expected_children: BTreeSet<String> = (1..=4)
        .map(|suffix| format!("asupersync-5z2scg.8.3.5.{suffix}"))
        .collect();
    let children = checked_array(receipt, "child_slices")?;
    if row_ids(children, "child_id") != expected_children {
        return Err("R3.5.5 child slice set drifted".to_owned());
    }
    if checked_json_sha256(receipt.get("child_slices").expect("checked child slices"))?
        != "b22a2217473d7d23b0d3638dd552cf8f2ecbdef4b2c4f5c23ad0f12d885a3bee"
    {
        return Err(
            "R3.5.5 exact child revisions, references, or terminal states drifted".to_owned(),
        );
    }
    let child_sources = [
        (
            "asupersync-5z2scg.8.3.5.1",
            "432be7270481c5439db00f79910465a269512266",
        ),
        (
            "asupersync-5z2scg.8.3.5.2",
            "51df97efd93c1c6ecb60ffff1021cfea032d7958",
        ),
        (
            "asupersync-5z2scg.8.3.5.3",
            "b12cc7ad426805f0c59ec343139ca1da8aefa448",
        ),
        (
            "asupersync-5z2scg.8.3.5.4",
            "da992970cbb0590014a36236682c138cd83b41a4",
        ),
    ];
    for (child_id, source_revision) in child_sources {
        let child = children
            .iter()
            .find(|row| row.get("child_id").and_then(Value::as_str) == Some(child_id))
            .ok_or_else(|| format!("missing child {child_id}"))?;
        if child.get("source_revision").and_then(Value::as_str) != Some(source_revision)
            || checked_array(child, "row_references")?.is_empty()
        {
            return Err(format!("child evidence drifted for {child_id}"));
        }
    }

    let join = checked_object(receipt, "row_join")?;
    for (key, expected) in [
        ("inherited_terminal_rows", 112),
        ("r3_5_1_owned_cases", 14),
        ("r3_5_1_owned_same_rows", 12),
        ("r3_5_1_owned_same_category_rows", 2),
        ("r3_5_4_compatibility_rows", 29),
        ("terminal_acceptance_clause_rows", 20),
        ("joined_stable_row_ids", 175),
        ("terminal_compatibility_binding_rows", 29),
        ("same_compatibility_rows", 7),
        ("keep_compatibility_rows", 22),
        ("typed_inherited_keep_rows", 3),
        ("unknown_rows", 0),
    ] {
        if join.get(key).and_then(Value::as_u64) != Some(expected) {
            return Err(format!("row_join.{key} drifted"));
        }
    }

    let clauses = checked_array(receipt, "child_acceptance_clause_rows")?;
    if clauses.len() != 20 || row_ids(clauses, "clause_id").len() != 20 {
        return Err("R3.5.5 must retain 20 unique child acceptance clauses".to_owned());
    }
    if checked_json_sha256(
        receipt
            .get("child_acceptance_clause_rows")
            .expect("checked child clauses"),
    )? != "864f1f82f349edd212b55f2ffb2c16f28c57bdd14dab2c4b95e1287326aa3bdb"
    {
        return Err("R3.5.5 exact child acceptance clauses drifted".to_owned());
    }
    for clause in clauses {
        if !matches!(
            checked_text(clause, "disposition")?,
            "SAME" | "BETTER" | "KEEP"
        ) || checked_text(clause, "evidence")?.is_empty()
        {
            return Err("child acceptance clauses must be explicit and evidenced".to_owned());
        }
    }

    let extension = map
        .get("r3_5_4_compatibility_extension")
        .ok_or_else(|| "R3.5.4 extension is required".to_owned())?;
    let compatibility_rows = checked_array(extension, "capability_rows")?;
    let bindings = checked_array(receipt, "compatibility_row_bindings")?;
    let compatibility_ids = row_ids(compatibility_rows, "surface_id");
    if bindings.len() != 29
        || row_ids(bindings, "capability_id").len() != 29
        || row_ids(bindings, "capability_id") != compatibility_ids
    {
        return Err("every compatibility row needs exactly one stable binding".to_owned());
    }
    if checked_json_sha256(
        receipt
            .get("compatibility_row_bindings")
            .expect("checked compatibility bindings"),
    )? != "1922c834a6b3ad16d421d197f48d32f7c78fee2de97d199c8f69344ebd7ad1d2"
    {
        return Err(
            "R3.5.5 exact case, replay, disposition, or no-claim binding drifted".to_owned(),
        );
    }
    let allowed_replay_lanes: BTreeSet<String> = [
        "r3_5_terminal_regex_source",
        "r3_5_terminal_public_contract",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect();
    let mut same_count = 0;
    let mut keep_count = 0;
    for binding in bindings {
        let capability_id = checked_text(binding, "capability_id")?;
        let source_row = compatibility_rows
            .iter()
            .find(|row| row.get("surface_id").and_then(Value::as_str) == Some(capability_id))
            .ok_or_else(|| format!("missing compatibility source row {capability_id}"))?;
        let disposition = checked_text(binding, "disposition")?;
        if disposition != checked_text(source_row, "disposition")? {
            return Err(format!("{capability_id} disposition drifted"));
        }
        match disposition {
            "SAME" => same_count += 1,
            "KEEP" => keep_count += 1,
            _ => return Err(format!("{capability_id} has an unsupported disposition")),
        }
        if checked_text(binding, "source_revision")? != "903de8267e50fc5ba5652766157bd2083aee6e4c"
            || checked_text(binding, "evidence_base_revision")?
                != "903de8267e50fc5ba5652766157bd2083aee6e4c"
            || checked_array(binding, "case_ids")?.is_empty()
            || checked_array(binding, "case_ids")?
                .iter()
                .any(|value| value.as_str().is_none_or(str::is_empty))
            || checked_string_set(binding, "replay_lane_ids")?.is_empty()
            || !checked_string_set(binding, "replay_lane_ids")?.is_subset(&allowed_replay_lanes)
            || checked_text(binding, "no_claim")?.is_empty()
        {
            return Err(format!("{capability_id} has incomplete terminal metadata"));
        }
    }
    if (same_count, keep_count) != (7, 22) {
        return Err("R3.5.5 compatibility partition must remain 7 SAME / 22 KEEP".to_owned());
    }

    let boundaries = receipt
        .get("known_keep_boundaries")
        .ok_or_else(|| "known_keep_boundaries is required".to_owned())?;
    if checked_json_sha256(boundaries)?
        != "a33dd5a577bb0a9c15556a074e3b0ef2bdb59f32715cbf25ac56ab522857eaf7"
    {
        return Err("R3.5.5 exact KEEP boundaries or owners drifted".to_owned());
    }
    if checked_string_set(boundaries, "typed_inherited_row_ids")?
        != ["RGX-COMP-Q-009", "RGX-COMP-Q-010", "RGX-R324-U001"]
            .into_iter()
            .map(str::to_owned)
            .collect()
        || checked_array(boundaries, "historical_evidence_limitations")?.len() != 4
    {
        return Err("typed gaps and historical limitations must remain explicit".to_owned());
    }
    let routed = checked_array(boundaries, "routed_critical_or_high_gaps")?;
    if row_ids(routed, "gap_id") != expected_high_gaps
        || routed.iter().any(|row| {
            row.get("state").and_then(Value::as_str) != Some("ROUTED")
                || row
                    .get("owner")
                    .and_then(Value::as_str)
                    .is_none_or(str::is_empty)
                || !matches!(
                    row.get("severity").and_then(Value::as_str),
                    Some("critical" | "high")
                )
        })
    {
        return Err("routed critical/high gap details are incomplete".to_owned());
    }
    for row in routed {
        let gap_id = checked_text(row, "gap_id")?;
        let inventory_row = checked_array(inventory, "gaps")?
            .iter()
            .find(|candidate| candidate.get("gap_id").and_then(Value::as_str) == Some(gap_id))
            .ok_or_else(|| format!("routed gap {gap_id} is absent from the pinned inventory"))?;
        for key in ["severity", "owner", "state"] {
            if checked_text(row, key)? != checked_text(inventory_row, key)? {
                return Err(format!("routed gap {gap_id} {key} drifted from inventory"));
            }
        }
    }

    let mut joined_ids = BTreeSet::new();
    for family in checked_array(map, "inherited_terminal_row_families")? {
        let ids = checked_array(family, "row_ids")?;
        if family.get("row_count").and_then(Value::as_u64) != Some(ids.len() as u64) {
            return Err(format!(
                "{} row count drifted",
                checked_text(family, "family_id")?
            ));
        }
        for id in ids {
            let id = id
                .as_str()
                .ok_or_else(|| "inherited row IDs must be strings".to_owned())?;
            if !joined_ids.insert(id.to_owned()) {
                return Err(format!("duplicate terminal row ID {id}"));
            }
        }
    }
    for (rows, key) in [
        (checked_array(map, "r3_5_owned_case_contract")?, "case_id"),
        (compatibility_rows, "surface_id"),
        (clauses, "clause_id"),
    ] {
        for row in rows {
            let id = checked_text(row, key)?;
            if !joined_ids.insert(id.to_owned()) {
                return Err(format!("duplicate terminal row ID {id}"));
            }
        }
    }
    if joined_ids.len() != 175 {
        return Err(format!(
            "terminal row join must contain 175 globally unique IDs, found {}",
            joined_ids.len()
        ));
    }

    let replay = checked_array(receipt, "replay_metadata")?;
    let replay_ids = row_ids(replay, "lane");
    let final_validation_boundary = serde_json::json!({
        "self_referential_receipt_update_forbidden": true,
        "embedded_public_replay_scope": "exact pre-final candidate overlay; not proof of final receipt bytes",
        "finalized_overlay_validation_required_after_last_receipt_edit": true,
        "finalized_overlay_receipt_location": "Bead asupersync-5z2scg.8.3.5.5 closure comment and commit handoff"
    });
    if receipt.get("final_validation_boundary") != Some(&final_validation_boundary) {
        return Err("finalized-overlay validation boundary drifted".to_owned());
    }
    let gap_replay = replay
        .iter()
        .find(|row| {
            row.get("lane").and_then(Value::as_str) == Some("r3_5_gap_01_fail_closed_regression")
        })
        .ok_or_else(|| "missing GAP-01 historical replay lane".to_owned())?;
    if gap_replay
        .get("metadata_completeness")
        .and_then(Value::as_str)
        != Some("PARTIAL_HISTORICAL")
        || gap_replay.get("result").and_then(Value::as_str) != Some("PASS_1_OF_1")
        || gap_replay.get("remote_required").and_then(Value::as_bool) != Some(true)
        || gap_replay
            .get("local_fallback_used")
            .and_then(Value::as_bool)
            != Some(false)
        || checked_string_set(gap_replay, "missing_fields")?
            != [
                "finished_at",
                "full_rch_command",
                "requested_cargo_target_dir",
                "observed_remote_workspace",
                "observed_remote_target_dir",
                "clean_overlay_base_revision",
                "overlay_paths",
                "overlay_fingerprint",
            ]
            .into_iter()
            .map(str::to_owned)
            .collect()
    {
        return Err("GAP-01 historical replay limitations must remain exact".to_owned());
    }

    let exact_current_replays = [
        serde_json::json!({
            "lane": "r3_5_terminal_regex_source",
            "job_id": 29985909466202189_u64,
            "worker": "ovh-a",
            "started_at": "2026-08-21T12:28:03.514420956Z",
            "finished_at": "2026-08-21T12:34:18.802639Z",
            "source_revision": "903de8267e50fc5ba5652766157bd2083aee6e4c",
            "command": "cargo test -j 4 -p asupersync --lib --features metrics observability::regex -- --nocapture",
            "full_rch_command": "RCH_WORKER=ovh-a RCH_REQUIRE_REMOTE=1 rch exec --base 903de8267e50fc5ba5652766157bd2083aee6e4c --clean-overlay --no-overlay -- env CARGO_TARGET_DIR=${RCH_TARGET_BASE:-${TMPDIR:-/tmp}}/rch_target_regex_source_r355 CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 RUSTFLAGS='-D warnings -C debuginfo=0' cargo test -j 4 -p asupersync --lib --features metrics observability::regex -- --nocapture",
            "requested_cargo_target_dir": "/data/tmp/rch_target_regex_source_r355",
            "observed_remote_workspace": "/data/tmp/rch/asupersync/4fe30dfc059ad51a",
            "observed_remote_target_dir": "/data/tmp/rch/asupersync/4fe30dfc059ad51a/.rch-target-ovh-a-pool-5df3061708e292ffc39ef9f9f124e41a",
            "clean_overlay": true,
            "clean_overlay_base_revision": "903de8267e50fc5ba5652766157bd2083aee6e4c",
            "no_overlay": true,
            "overlay_paths": [],
            "overlay_fingerprint": "fe0d5151031be8fda7951fe7fe1f42f7ce344018fdb3ed21e6ada866b230b195",
            "working_tree_mode": "CLEAN_COMMITTED_BASE_NO_OVERLAY",
            "peer_dirt_excluded": true,
            "result": "PASS_112_OF_112",
            "remote_required": true,
            "local_fallback_used": false,
            "metadata_completeness": "CURRENT_EXACT"
        }),
        serde_json::json!({
            "lane": "r3_5_terminal_public_contract",
            "job_id": 29985909466202188_u64,
            "worker": "ovh-a",
            "started_at": "2026-08-21T12:25:57.588752801Z",
            "finished_at": "2026-08-21T12:27:48.280393Z",
            "source_revision": "903de8267e50fc5ba5652766157bd2083aee6e4c",
            "command": "cargo test -j 4 -p asupersync --features metrics --test regex_privacy_capability_inventory_contract -- --nocapture",
            "full_rch_command": "RCH_WORKER=ovh-a RCH_REQUIRE_REMOTE=1 rch exec --base 903de8267e50fc5ba5652766157bd2083aee6e4c --clean-overlay --overlay-path artifacts/regex_privacy_capability_inventory_v1.json --overlay-path artifacts/regex_private_compile_api_map_v1.json --overlay-path docs/regex_private_compile_api_map.md --overlay-path tests/regex_privacy_capability_inventory_contract.rs -- env CARGO_TARGET_DIR=${RCH_TARGET_BASE:-${TMPDIR:-/tmp}}/rch_target_regex_config_r354 CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 RUSTFLAGS='-D warnings -C debuginfo=0' cargo test -j 4 -p asupersync --features metrics --test regex_privacy_capability_inventory_contract -- --nocapture",
            "requested_cargo_target_dir": "/data/tmp/rch_target_regex_config_r354",
            "observed_remote_workspace": "/data/tmp/rch/asupersync/cc75160aaf2fa8ba",
            "observed_remote_target_dir": "/data/tmp/rch/asupersync/cc75160aaf2fa8ba/.rch-target-ovh-a-pool-5df3061708e292ffc39ef9f9f124e41a",
            "clean_overlay": true,
            "clean_overlay_base_revision": "903de8267e50fc5ba5652766157bd2083aee6e4c",
            "overlay_paths": [
                "artifacts/regex_privacy_capability_inventory_v1.json",
                "artifacts/regex_private_compile_api_map_v1.json",
                "docs/regex_private_compile_api_map.md",
                "tests/regex_privacy_capability_inventory_contract.rs"
            ],
            "overlay_fingerprint": "2e1c1e700c1ce1f1e8877097f49fc570ed8ffd9861ba9d2b069b5c4ce8a7292b",
            "working_tree_mode": "CLEAN_BASE_PLUS_EXPLICIT_OVERLAY",
            "peer_dirt_excluded": true,
            "result": "PASS_13_OF_13",
            "remote_required": true,
            "local_fallback_used": false,
            "metadata_completeness": "EXACT_CANDIDATE_PRE_FINAL_RECEIPT",
            "provenance_scope": "does not prove final receipt bytes; finalized overlay validation is retained externally after the last receipt edit"
        }),
    ];
    let captured_at = checked_text(receipt, "captured_at_utc")?;
    for expected in exact_current_replays {
        let lane = checked_text(&expected, "lane")?;
        if !replay_ids.contains(lane) {
            return Err(format!("missing current replay lane {lane}"));
        }
        let actual = replay
            .iter()
            .find(|row| row.get("lane").and_then(Value::as_str) == Some(lane))
            .expect("checked current replay lane");
        if actual != &expected {
            return Err(format!("current replay lane {lane} provenance drifted"));
        }
        if checked_text(actual, "finished_at")? >= captured_at {
            return Err(format!("receipt capture predates replay lane {lane}"));
        }
    }

    let no_claims = checked_array(receipt, "no_claims")?;
    if no_claims.len() != 13
        || no_claims
            .iter()
            .any(|claim| claim.as_str().is_none_or(str::is_empty))
    {
        return Err("R3.5.5 no-claim boundary drifted".to_owned());
    }
    if checked_json_sha256(receipt.get("no_claims").expect("checked no-claims"))?
        != "72829d23dc443085eca79a500b76953c9c21dd7bde2d653c03a71f610d24db77"
    {
        return Err("R3.5.5 exact no-claim wording drifted".to_owned());
    }
    if map.get("no_claims") != receipt.get("no_claims") {
        return Err(
            "artifact-global no-claims must match the current terminal boundary".to_owned(),
        );
    }

    let doc = read_repo_file("docs/regex_private_compile_api_map.md");
    for marker in [
        "BEGIN R3.5.5 PRIVATE API TERMINAL RECEIPT",
        "ASUP-REGEX-R3-5-PRIVATE-API-TERMINAL-V1",
        "KEEP_INCUMBENT_DEFER",
        "29 exact compatibility rows",
        "7 `SAME`, 22 `KEEP`",
        "R3.7.1 independent verification may proceed",
        "Seven routed critical/high findings remain visible",
        "does not authorize a public re-export",
        "END R3.5.5 PRIVATE API TERMINAL RECEIPT",
    ] {
        if !doc.contains(marker) {
            return Err(format!("R3.5.5 documentation must retain {marker}"));
        }
    }
    Ok(())
}

#[test]
fn r3_5_5_terminal_receipt_joins_every_child_and_fails_closed() {
    let map = parse_repo_json(PRIVATE_API_MAP_PATH);
    let inventory = artifact();
    validate_r3_5_5_terminal(&map, &inventory).unwrap_or_else(|error| panic!("{error}"));

    let mut public_cutover = map.clone();
    public_cutover["r3_5_5_terminal_receipt"]["decision"]["public_reexport_authorized"] =
        Value::Bool(true);
    assert!(validate_r3_5_5_terminal(&public_cutover, &inventory).is_err());

    let mut unknown = map.clone();
    unknown["r3_5_5_terminal_receipt"]["compatibility_row_bindings"][0]["disposition"] =
        Value::String("UNKNOWN".to_owned());
    assert!(validate_r3_5_5_terminal(&unknown, &inventory).is_err());

    let mut missing_binding = map.clone();
    missing_binding["r3_5_5_terminal_receipt"]["compatibility_row_bindings"]
        .as_array_mut()
        .expect("binding array")
        .pop();
    assert!(validate_r3_5_5_terminal(&missing_binding, &inventory).is_err());

    let mut missing_case = map.clone();
    missing_case["r3_5_5_terminal_receipt"]["compatibility_row_bindings"][0]["case_ids"] =
        Value::Array(Vec::new());
    assert!(validate_r3_5_5_terminal(&missing_case, &inventory).is_err());

    let mut hidden_gap = map.clone();
    hidden_gap["r3_5_5_terminal_receipt"]["decision"]["unresolved_critical_or_high_gap_ids"]
        .as_array_mut()
        .expect("gap array")
        .pop();
    assert!(validate_r3_5_5_terminal(&hidden_gap, &inventory).is_err());

    let mut new_hidden_high = inventory.clone();
    let new_gap = serde_json::json!({
        "gap_id": "RGX-R1-GAP-15",
        "severity": "high",
        "state": "ROUTED",
        "owner": "asupersync-hidden-owner",
        "summary": "synthetic hidden high gap"
    });
    new_hidden_high["gaps"]
        .as_array_mut()
        .expect("gap array")
        .push(new_gap);
    assert!(validate_r3_5_5_terminal(&map, &new_hidden_high).is_err());

    let mut stale_source = map.clone();
    stale_source["r3_5_5_terminal_receipt"]["compatibility_row_bindings"][0]["source_revision"] =
        Value::String("stale".to_owned());
    assert!(validate_r3_5_5_terminal(&stale_source, &inventory).is_err());

    let mut stale_child_evidence = map.clone();
    stale_child_evidence["r3_5_5_terminal_receipt"]["child_slices"][0]["evidence_revisions"][0] =
        Value::String("stale".to_owned());
    assert!(validate_r3_5_5_terminal(&stale_child_evidence, &inventory).is_err());

    let mut wrong_clause_owner = map.clone();
    wrong_clause_owner["r3_5_5_terminal_receipt"]["child_acceptance_clause_rows"][0]["child_id"] =
        Value::String("asupersync-wrong-child".to_owned());
    assert!(validate_r3_5_5_terminal(&wrong_clause_owner, &inventory).is_err());

    let mut wrong_owner_bead = map.clone();
    wrong_owner_bead["r3_5_5_terminal_receipt"]["known_keep_boundaries"]["remaining_owner_beads"]
        [0] = Value::String("asupersync-wrong-owner".to_owned());
    assert!(validate_r3_5_5_terminal(&wrong_owner_bead, &inventory).is_err());

    let mut weakened_no_claim = map.clone();
    weakened_no_claim["r3_5_5_terminal_receipt"]["no_claims"][0] =
        Value::String("no claim".to_owned());
    assert!(validate_r3_5_5_terminal(&weakened_no_claim, &inventory).is_err());

    let mut stale_global_no_claim = map.clone();
    stale_global_no_claim["no_claims"][0] = Value::String("stale historical claim".to_owned());
    assert!(validate_r3_5_5_terminal(&stale_global_no_claim, &inventory).is_err());

    let mut premature_capture = map.clone();
    premature_capture["r3_5_5_terminal_receipt"]["captured_at_utc"] =
        Value::String("2026-08-21T11:54:32Z".to_owned());
    assert!(validate_r3_5_5_terminal(&premature_capture, &inventory).is_err());

    let mut local_fallback = map.clone();
    let replay = local_fallback["r3_5_5_terminal_receipt"]["replay_metadata"]
        .as_array_mut()
        .expect("replay array");
    let current = replay
        .iter_mut()
        .find(|row| {
            row.get("lane").and_then(Value::as_str) == Some("r3_5_gap_01_fail_closed_regression")
        })
        .expect("current regression lane");
    current["local_fallback_used"] = Value::Bool(true);
    assert!(validate_r3_5_5_terminal(&local_fallback, &inventory).is_err());

    let mut zero_test_pass = map.clone();
    let replay = zero_test_pass["r3_5_5_terminal_receipt"]["replay_metadata"]
        .as_array_mut()
        .expect("replay array");
    let current = replay
        .iter_mut()
        .find(|row| {
            row.get("lane").and_then(Value::as_str) == Some("r3_5_terminal_public_contract")
        })
        .expect("terminal public lane");
    current["result"] = Value::String("PASS_0_OF_0".to_owned());
    assert!(validate_r3_5_5_terminal(&zero_test_pass, &inventory).is_err());

    let mut missing_rch_command = map.clone();
    missing_rch_command["r3_5_5_terminal_receipt"]["replay_metadata"]
        .as_array_mut()
        .expect("replay array")
        .iter_mut()
        .find(|row| {
            row.get("lane").and_then(Value::as_str) == Some("r3_5_terminal_public_contract")
        })
        .expect("terminal public lane")
        .as_object_mut()
        .expect("terminal public row")
        .remove("full_rch_command");
    assert!(validate_r3_5_5_terminal(&missing_rch_command, &inventory).is_err());

    let mut stale_pin = map.clone();
    stale_pin["r3_5_5_terminal_receipt"]["predecessor_receipts"][0]["sha256"] =
        Value::String("stale".to_owned());
    assert!(validate_r3_5_5_terminal(&stale_pin, &inventory).is_err());
}

fn quoted_codes(path: &str, prefix: &str) -> BTreeSet<String> {
    read_repo_file(path)
        .split('"')
        .skip(1)
        .step_by(2)
        .filter(|value| value.starts_with(prefix))
        .map(str::to_owned)
        .collect()
}

fn validate_current_pin(
    pin: &Value,
    producer_ids: Option<&BTreeSet<String>>,
) -> Result<(), String> {
    let path = checked_text(pin, "path")?;
    let bytes = read_repo_bytes(path);
    let actual_sha256 = hex::encode(Sha256::digest(&bytes));
    let actual_line_count = read_repo_file(path).lines().count() as u64;
    let expected_sha256 = checked_text(pin, "sha256")?;
    let expected_line_count = pin.get("line_count").and_then(Value::as_u64);
    let hash_matches = expected_sha256.as_bytes() == actual_sha256.as_bytes();
    let line_count_matches = expected_line_count == Some(actual_line_count);
    if !hash_matches || !line_count_matches {
        return Err(format!(
            "current R3.7.1 pin drifted for {path}: expected_sha256={} actual_sha256={actual_sha256} expected_lines={:?} actual_lines={actual_line_count}",
            expected_sha256, expected_line_count
        ));
    }
    if let Some(producer_ids) = producer_ids {
        let producer_id = checked_text(pin, "producer_id")?;
        if !producer_ids.contains(producer_id) {
            return Err(format!("{path} names unknown producer {producer_id}"));
        }
    }
    Ok(())
}

fn validate_r3_7_1_full_surface_join(map: &Value) -> Result<(), String> {
    let join = map
        .get("r3_7_1_full_surface_corpus_join")
        .ok_or_else(|| "r3_7_1_full_surface_corpus_join is required".to_owned())?;
    validate_no_unknown(join, "$.r3_7_1_full_surface_corpus_join")?;

    for (key, expected) in [
        ("join_id", "ASUP-REGEX-R3-7-1-FULL-SURFACE-CORPUS-V1"),
        ("bead_id", "asupersync-5z2scg.8.3.7.1"),
        ("capability_id", CAPABILITY_ID),
        (
            "evidence_base_revision",
            "a62d5f75fcb5a934c24ff6afda66c497f44d1b23",
        ),
    ] {
        if checked_text(join, key)? != expected {
            return Err(format!("R3.7.1 {key} drifted"));
        }
    }
    if join.get("join_schema_version").and_then(Value::as_u64) != Some(1) {
        return Err("R3.7.1 join schema must remain v1".to_owned());
    }

    let decision = checked_object(join, "decision")?;
    if decision.get("state").and_then(Value::as_str)
        != Some("VERIFICATION_READY_KEEP_INCUMBENT_DEFER")
        || decision.get("unknown_rows").and_then(Value::as_u64) != Some(0)
        || decision
            .get("incumbent_only_normative_cases")
            .and_then(Value::as_u64)
            != Some(0)
        || decision
            .get("r3_7_terminal_decision_ready")
            .and_then(Value::as_bool)
            != Some(false)
    {
        return Err("R3.7.1 decision must remain verification-only and fail-closed".to_owned());
    }
    for forbidden in [
        "public_reexport_authorized",
        "privacy_config_integration_authorized",
        "production_wiring_authorized",
        "dependency_removal_authorized",
    ] {
        if decision.get(forbidden).and_then(Value::as_bool) != Some(false) {
            return Err(format!("R3.7.1 must not authorize {forbidden}"));
        }
    }

    let producers = checked_array(join, "producer_registry")?;
    let producer_ids = row_ids(producers, "producer_id");
    if producers.len() != 8 || producer_ids.len() != 8 {
        return Err("R3.7.1 requires eight unique producers".to_owned());
    }
    for producer in producers {
        let producer_id = checked_text(producer, "producer_id")?;
        if checked_text(producer, "kind")?.is_empty()
            || checked_text(producer, "name")?.is_empty()
            || checked_text(producer, "version")?.is_empty()
            || checked_text(producer, "license")?.is_empty()
        {
            return Err(format!("producer {producer_id} has incomplete provenance"));
        }
        let incumbent_only = producer
            .get("incumbent_only")
            .and_then(Value::as_bool)
            .ok_or_else(|| format!("producer {producer_id} needs incumbent_only"))?;
        let normative = producer
            .get("normative")
            .and_then(Value::as_bool)
            .ok_or_else(|| format!("producer {producer_id} needs normative"))?;
        if incumbent_only == normative {
            return Err(format!(
                "producer {producer_id} must be either normative or incumbent-only"
            ));
        }
    }
    let incumbent = producers
        .iter()
        .find(|row| {
            row.get("producer_id").and_then(Value::as_str) == Some("RGX-PRODUCER-INCUMBENT")
        })
        .ok_or_else(|| "missing quarantined incumbent producer".to_owned())?;
    if checked_text(incumbent, "review_or_expiry_utc")? != "2026-10-23T00:00:00Z"
        || checked_text(incumbent, "on_expiry")? != "KEEP_INCUMBENT_DEFER"
    {
        return Err("incumbent oracle expiry must remain explicit and fail-closed".to_owned());
    }

    let live_pins = checked_array(join, "live_source_pins")?;
    let expected_live_paths: BTreeSet<String> = [
        "src/observability/regex_syntax.rs",
        "src/observability/regex_semantics.rs",
        "src/observability/regex_boundaries.rs",
        "src/observability/regex_ir.rs",
        "src/observability/regex_lowering.rs",
        "src/observability/regex_vm.rs",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect();
    if live_pins.len() != expected_live_paths.len()
        || row_ids(live_pins, "path") != expected_live_paths
    {
        return Err("live regex source pin set drifted".to_owned());
    }
    for pin in live_pins {
        validate_current_pin(pin, None)?;
        if checked_text(pin, "revision")?.len() != 40 {
            return Err(format!(
                "{} has invalid revision",
                checked_text(pin, "path")?
            ));
        }
    }

    let producer_pins = checked_array(join, "producer_artifact_pins")?;
    if producer_pins.len() != 8 || row_ids(producer_pins, "path").len() != 8 {
        return Err("producer artifact pin set drifted".to_owned());
    }
    for pin in producer_pins {
        validate_current_pin(pin, Some(&producer_ids))?;
    }
    let executable_pins = checked_array(join, "executable_source_pins")?;
    if executable_pins.len() != 9 || row_ids(executable_pins, "path").len() != 9 {
        return Err("executable corpus source pin set drifted".to_owned());
    }
    for pin in executable_pins {
        validate_current_pin(pin, None)?;
    }

    let upstream = checked_array(join, "official_upstream_file_pins")?;
    let expected_upstream: BTreeSet<String> = [
        "regex-1.13.1/testdata/unicode.toml",
        "regex-1.13.1/testdata/bytes.toml",
        "regex-1.13.1/testdata/iter.toml",
        "regex-1.13.1/testdata/regression.toml",
        "regex-1.13.1/testdata/word-boundary.toml",
        "regex-1.13.1/testdata/flags.toml",
        "regex-1.13.1/testdata/crlf.toml",
        "regex-1.13.1/testdata/no-unicode.toml",
        "regex-1.13.1/tests/replace.rs",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect();
    if upstream.len() != 9 || row_ids(upstream, "path") != expected_upstream {
        return Err("official regex source-file inventory drifted".to_owned());
    }
    for pin in upstream {
        if checked_text(pin, "sha256")?.len() != 64
            || pin
                .get("line_count")
                .and_then(Value::as_u64)
                .is_none_or(|count| count == 0)
        {
            return Err(format!(
                "official source pin {} is incomplete",
                checked_text(pin, "path")?
            ));
        }
    }
    let lock = read_repo_file("Cargo.lock");
    for marker in [
        "name = \"regex\"\nversion = \"1.13.1\"",
        "checksum = \"f020237b6c8eed93db2e2cb53c00c60a8e1bc73da7d073199a1180401450218d\"",
        "name = \"regex-syntax\"\nversion = \"0.8.11\"",
        "checksum = \"d6f6ff9a378485b298a5286656da665ba74413d36db0979633275d2e708145d4\"",
    ] {
        if !lock.contains(marker) {
            return Err(format!("Cargo.lock lost R3.7.1 oracle pin {marker}"));
        }
    }

    let compatibility_rows = checked_array(
        map.get("r3_5_4_compatibility_extension")
            .ok_or_else(|| "R3.5.4 extension is required".to_owned())?,
        "capability_rows",
    )?;
    let compatibility_ids = row_ids(compatibility_rows, "surface_id");
    let surfaces = checked_array(join, "surface_rows")?;
    let cases = checked_array(join, "coverage_cases")?;
    if surfaces.len() != 12 || row_ids(surfaces, "surface_id").len() != 12 {
        return Err("R3.7.1 must retain 12 unique full-surface rows".to_owned());
    }
    if cases.len() != 36 || row_ids(cases, "case_id").len() != 36 {
        return Err("R3.7.1 must retain 36 unique triad cases".to_owned());
    }
    let mut joined_capabilities = BTreeSet::new();
    for surface in surfaces {
        let surface_id = checked_text(surface, "surface_id")?;
        let case_ids = checked_string_set(surface, "case_ids")?;
        let surface_cases: Vec<&Value> = cases
            .iter()
            .filter(|row| row.get("surface_id").and_then(Value::as_str) == Some(surface_id))
            .collect();
        let surface_case_ids: BTreeSet<String> = surface_cases
            .iter()
            .map(|row| checked_text(row, "case_id").map(str::to_owned))
            .collect::<Result<_, _>>()?;
        let coverage_kinds: BTreeSet<String> = surface_cases
            .iter()
            .map(|row| checked_text(row, "coverage_kind").map(str::to_owned))
            .collect::<Result<_, _>>()?;
        if surface_cases.len() != 3
            || case_ids != surface_case_ids
            || coverage_kinds
                != ["positive", "boundary", "malformed"]
                    .into_iter()
                    .map(str::to_owned)
                    .collect()
        {
            return Err(format!(
                "surface {surface_id} lost its exact coverage triad"
            ));
        }
        for capability_id in checked_array(surface, "capability_ids")? {
            let capability_id = capability_id
                .as_str()
                .ok_or_else(|| format!("{surface_id} capability IDs must be strings"))?;
            if !joined_capabilities.insert(capability_id.to_owned()) {
                return Err(format!("duplicate capability mapping {capability_id}"));
            }
        }
    }
    if joined_capabilities != compatibility_ids {
        return Err("R3.7.1 must map every exact R3.5.4 capability once".to_owned());
    }

    let allowed_evidence_paths: BTreeSet<String> = live_pins
        .iter()
        .chain(producer_pins)
        .chain(executable_pins)
        .map(|pin| checked_text(pin, "path").map(str::to_owned))
        .collect::<Result<_, _>>()?;
    for case in cases {
        let case_id = checked_text(case, "case_id")?;
        let path = checked_text(case, "source_path")?;
        let selector = checked_text(case, "selector")?;
        if !allowed_evidence_paths.contains(path) || !read_repo_file(path).contains(selector) {
            return Err(format!(
                "case {case_id} has stale evidence selector {path}:{selector}"
            ));
        }
        if checked_text(case, "normalized_expectation")?.is_empty()
            || case.get("incumbent_is_normative").and_then(Value::as_bool) != Some(false)
        {
            return Err(format!(
                "case {case_id} has invalid normalized expectation policy"
            ));
        }
        let case_producers = checked_string_set(case, "producer_ids")?;
        if case_producers.is_empty() || !case_producers.is_subset(&producer_ids) {
            return Err(format!("case {case_id} has missing or unknown producers"));
        }
        if !case_producers.iter().any(|producer_id| {
            producers.iter().any(|producer| {
                producer.get("producer_id").and_then(Value::as_str) == Some(producer_id)
                    && producer.get("normative").and_then(Value::as_bool) == Some(true)
            })
        }) {
            return Err(format!(
                "case {case_id} has only a quarantined incumbent producer"
            ));
        }
    }

    let families = checked_array(join, "error_family_rows")?;
    if families.len() != 11 || row_ids(families, "family_id").len() != 11 {
        return Err("R3.7.1 stable error family set drifted".to_owned());
    }
    let mut joined_codes = BTreeSet::new();
    for family in families {
        let family_id = checked_text(family, "family_id")?;
        let source_path = checked_text(family, "source_path")?;
        let prefix = checked_text(family, "prefix")?;
        let declared_codes = checked_string_set(family, "codes")?;
        let current_codes = quoted_codes(source_path, prefix);
        if declared_codes != current_codes {
            return Err(format!("{family_id} live stable-code census drifted"));
        }
        for code in declared_codes {
            if !joined_codes.insert(code.clone()) {
                return Err(format!("duplicate live stable error code {code}"));
            }
        }
        let family_cases = checked_string_set(family, "coverage_case_ids")?;
        let kinds: BTreeSet<String> = family_cases
            .iter()
            .map(|case_id| {
                let case = cases
                    .iter()
                    .find(|row| row.get("case_id").and_then(Value::as_str) == Some(case_id))
                    .ok_or_else(|| format!("{family_id} references missing case {case_id}"))?;
                checked_text(case, "coverage_kind").map(str::to_owned)
            })
            .collect::<Result<_, _>>()?;
        if family_cases.len() != 3
            || kinds
                != ["positive", "boundary", "malformed"]
                    .into_iter()
                    .map(str::to_owned)
                    .collect()
        {
            return Err(format!(
                "{family_id} lost positive/boundary/malformed coverage"
            ));
        }
    }
    if joined_codes.len() != 122 {
        return Err(format!(
            "R3.7.1 must bind 122 unique live stable codes, found {}",
            joined_codes.len()
        ));
    }
    let lowering = families
        .iter()
        .find(|row| row.get("family_id").and_then(Value::as_str) == Some("RGX-R371-ERROR-LOWER"))
        .ok_or_else(|| "missing lowering error family".to_owned())?;
    if checked_string_set(lowering, "retired_predecessor_codes")?
        != ["RGX-LOWER-E007", "RGX-LOWER-E008"]
            .into_iter()
            .map(str::to_owned)
            .collect()
        || joined_codes.contains("RGX-LOWER-E007")
        || joined_codes.contains("RGX-LOWER-E008")
    {
        return Err("retired lowering codes must not reappear as live errors".to_owned());
    }

    let generators = checked_array(join, "generated_producers")?;
    if generators.len() != 4 || row_ids(generators, "generator_id").len() != 4 {
        return Err("R3.7.1 deterministic generator set drifted".to_owned());
    }
    for generator in generators {
        let path = checked_text(generator, "source_path")?;
        let selector = checked_text(generator, "selector")?;
        if !allowed_evidence_paths.contains(path)
            || !read_repo_file(path).contains(selector)
            || checked_text(generator, "normalized_expectation")?.is_empty()
        {
            return Err(format!(
                "generator {} has stale source or outcome",
                checked_text(generator, "generator_id")?
            ));
        }
    }

    for (key, expected) in [
        ("accepted_capability_rows", 29),
        ("same_rows", 7),
        ("keep_rows", 22),
        ("surface_rows", surfaces.len() as u64),
        ("coverage_cases", cases.len() as u64),
        ("live_error_codes", joined_codes.len() as u64),
    ] {
        if decision.get(key).and_then(Value::as_u64) != Some(expected) {
            return Err(format!("decision.{key} does not match derived coverage"));
        }
    }
    let dispositions: Vec<&str> = compatibility_rows
        .iter()
        .map(|row| checked_text(row, "disposition"))
        .collect::<Result<_, _>>()?;
    if dispositions
        .iter()
        .filter(|value| **value == "SAME")
        .count()
        != 7
        || dispositions
            .iter()
            .filter(|value| **value == "KEEP")
            .count()
            != 22
    {
        return Err("R3.7.1 may not promote or erase compatibility dispositions".to_owned());
    }

    let replay_value = join
        .get("replay")
        .ok_or_else(|| "R3.7.1 replay is required".to_owned())?;
    let replay = checked_object(join, "replay")?;
    if replay.get("remote_required").and_then(Value::as_bool) != Some(true)
        || replay.get("local_fallback_used").and_then(Value::as_bool) != Some(false)
        || !checked_text(replay_value, "focused_command")?.starts_with("cargo test ")
        || !checked_text(replay_value, "full_corpus_command")?
            .contains("--test regex_vm_terminal_receipt_contract")
        || !checked_text(replay_value, "source_unit_command")?.contains("observability::regex")
    {
        return Err(
            "R3.7.1 replay commands must remain exact, remote-only, and complete".to_owned(),
        );
    }
    let no_claims = checked_array(join, "no_claims")?;
    if no_claims.len() != 9
        || no_claims
            .iter()
            .any(|claim| claim.as_str().is_none_or(str::is_empty))
    {
        return Err("R3.7.1 no-claim boundary drifted".to_owned());
    }

    let doc = read_repo_file("docs/regex_private_compile_api_map.md");
    for marker in [
        "BEGIN R3.7.1 FULL-SURFACE CORPUS JOIN",
        "ASUP-REGEX-R3-7-1-FULL-SURFACE-CORPUS-V1",
        "122 live stable error codes",
        "positive / boundary / malformed",
        "incumbent is never the sole normative producer",
        "VERIFICATION_READY_KEEP_INCUMBENT_DEFER",
        "END R3.7.1 FULL-SURFACE CORPUS JOIN",
    ] {
        if !doc.contains(marker) {
            return Err(format!("R3.7.1 documentation must retain {marker}"));
        }
    }
    Ok(())
}

#[test]
fn r3_7_1_full_surface_join_is_current_complete_and_non_normative_to_incumbent() {
    let map = parse_repo_json(PRIVATE_API_MAP_PATH);
    validate_r3_7_1_full_surface_join(&map).unwrap_or_else(|error| panic!("{error}"));
}

#[test]
fn r3_7_1_full_surface_join_rejects_missing_stale_or_overclaimed_evidence() {
    let map = parse_repo_json(PRIVATE_API_MAP_PATH);

    let mut missing_surface = map.clone();
    missing_surface["r3_7_1_full_surface_corpus_join"]["surface_rows"]
        .as_array_mut()
        .expect("surface rows")
        .pop();
    assert!(validate_r3_7_1_full_surface_join(&missing_surface).is_err());

    let mut missing_case = map.clone();
    missing_case["r3_7_1_full_surface_corpus_join"]["coverage_cases"]
        .as_array_mut()
        .expect("coverage cases")
        .pop();
    assert!(validate_r3_7_1_full_surface_join(&missing_case).is_err());

    let mut missing_error = map.clone();
    missing_error["r3_7_1_full_surface_corpus_join"]["error_family_rows"][0]["codes"]
        .as_array_mut()
        .expect("error codes")
        .pop();
    assert!(validate_r3_7_1_full_surface_join(&missing_error).is_err());

    let mut stale_source = map.clone();
    stale_source["r3_7_1_full_surface_corpus_join"]["live_source_pins"][0]["sha256"] =
        Value::String("stale".to_owned());
    assert!(validate_r3_7_1_full_surface_join(&stale_source).is_err());

    let mut incumbent_normative = map.clone();
    incumbent_normative["r3_7_1_full_surface_corpus_join"]["coverage_cases"][0]["incumbent_is_normative"] =
        Value::Bool(true);
    assert!(validate_r3_7_1_full_surface_join(&incumbent_normative).is_err());

    let mut hidden_unknown = map.clone();
    hidden_unknown["r3_7_1_full_surface_corpus_join"]["decision"]["state"] =
        Value::String("UNKNOWN".to_owned());
    assert!(validate_r3_7_1_full_surface_join(&hidden_unknown).is_err());
}

#[test]
fn fail_closed_mutations_are_rejected() {
    let inventory = artifact();

    let mut dependency_exit = inventory.clone();
    dependency_exit["authority"]["dependency_exit_allowed"] = Value::Bool(true);
    assert!(validate_inventory(&dependency_exit).is_err());

    let mut scanner_overclaim = inventory.clone();
    scanner_overclaim["authority"]["fixed_scanners_are_general_replacement"] = Value::Bool(true);
    assert!(validate_inventory(&scanner_overclaim).is_err());

    let mut unknown = inventory.clone();
    unknown["public_surface"][0]["state"] = Value::String("UNKNOWN".to_owned());
    assert!(validate_inventory(&unknown).is_err());

    let mut missing_surface = inventory.clone();
    missing_surface["public_surface"]
        .as_array_mut()
        .expect("surface array")
        .pop();
    assert!(validate_inventory(&missing_surface).is_err());

    let mut missing_syntax = inventory.clone();
    missing_syntax["syntax_corpus"]
        .as_array_mut()
        .expect("syntax array")
        .pop();
    assert!(validate_inventory(&missing_syntax).is_err());

    let mut missing_gap = inventory.clone();
    missing_gap["gaps"].as_array_mut().expect("gap array").pop();
    assert!(validate_inventory(&missing_gap).is_err());
}
