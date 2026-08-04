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
            || !matches!(text(gap, "state"), "ROUTED" | "RESOLVED_BEFORE_BASELINE")
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
    assert!(source.contains("Regex::new(pattern).is_ok_and"));
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
    let mock = read_repo_file("src/net/atp/chunk/artifact.rs");
    let audit = read_repo_file("tests/otel_metric_attribute_denylist_audit.rs");
    assert_eq!(otel.matches("PrivacyConfig").count(), 17);
    assert_eq!(fixture.matches("PrivacyConfig").count(), 2);
    assert_eq!(otel.matches("SpanConfig").count(), 6);
    assert_eq!(otel.matches("regex::").count(), 2);
    assert_eq!(mock.matches("regex::").count(), 1);
    assert_eq!(audit.matches("regex::").count(), 1);
    assert_eq!(otel.matches("Regex").count(), 12);
    assert_eq!(mock.matches("Regex").count(), 3);
    assert!(mock.contains("mod regex"));
    assert!(mock.contains("pub struct Regex"));
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
    let mut valid_mutation = PrivacyConfig::new();
    valid_mutation.pii_patterns.push("secret-[0-9]+".to_owned());
    assert_eq!(valid_mutation.redact_pii("auth", "secret-42"), "[REDACTED]");

    let mut invalid_mutation = PrivacyConfig::new();
    invalid_mutation.pii_patterns.push("(".to_owned());
    assert_eq!(
        invalid_mutation.redact_pii("auth", "secret-42"),
        "secret-42",
        "RGX-R1-GAP-01 must remain executable until repaired by its owner"
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
        Some(4)
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
            Some(4)
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
