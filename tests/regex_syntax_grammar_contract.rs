//! Contract tests for `ASUP-REGEX-SYNTAX-V1`.
//!
//! Scope: versioned grammar/capability mapping, precedence, bounds, normalized
//! AST/diagnostic goldens, R1 coverage, and fail-closed mutation behavior.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::PathBuf;

use asupersync::observability::otel::PrivacyConfig;
use regex::Regex as IncumbentRegex;
use serde_json::Value;
use sha2::{Digest, Sha256};

const ARTIFACT_PATH: &str = "artifacts/regex_syntax_grammar_contract_v1.json";
const R1_ARTIFACT_PATH: &str = "artifacts/regex_privacy_capability_inventory_v1.json";
const DOC_PATH: &str = "docs/regex_syntax_grammar_contract.md";
const GRAMMAR_ID: &str = "ASUP-REGEX-SYNTAX-V1";
const CAPABILITY_ID: &str = "CAP-REGEX-PRIVACY";
const BEAD_ID: &str = "asupersync-5z2scg.8.3.1.1";

fn repo_path(relative: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(relative)
}

fn read_repo_file(relative: &str) -> String {
    fs::read_to_string(repo_path(relative))
        .unwrap_or_else(|error| panic!("failed to read {relative}: {error}"))
}

fn read_repo_bytes(relative: &str) -> Vec<u8> {
    fs::read(repo_path(relative))
        .unwrap_or_else(|error| panic!("failed to read {relative}: {error}"))
}

fn parse_repo_json(relative: &str) -> Value {
    serde_json::from_str(&read_repo_file(relative))
        .unwrap_or_else(|error| panic!("failed to parse {relative}: {error}"))
}

fn artifact() -> Value {
    parse_repo_json(ARTIFACT_PATH)
}

fn object<'a>(value: &'a Value, key: &str) -> &'a serde_json::Map<String, Value> {
    value
        .get(key)
        .and_then(Value::as_object)
        .unwrap_or_else(|| panic!("{key} must be an object"))
}

fn array<'a>(value: &'a Value, key: &str) -> &'a Vec<Value> {
    value
        .get(key)
        .and_then(Value::as_array)
        .unwrap_or_else(|| panic!("{key} must be an array"))
}

fn text<'a>(value: &'a Value, key: &str) -> &'a str {
    value
        .get(key)
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("{key} must be text"))
}

fn number(value: &Value, key: &str) -> u64 {
    value
        .get(key)
        .and_then(Value::as_u64)
        .unwrap_or_else(|| panic!("{key} must be an unsigned integer"))
}

fn row_ids(rows: &[Value], key: &str) -> BTreeSet<String> {
    rows.iter().map(|row| text(row, key).to_owned()).collect()
}

fn string_array(value: &Value, key: &str) -> BTreeSet<String> {
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

fn exact_set(values: &[&str]) -> BTreeSet<String> {
    values.iter().map(|value| (*value).to_owned()).collect()
}

fn validate_contract(contract: &Value) -> Result<(), String> {
    if number(contract, "schema_version") != 1
        || text(contract, "artifact_id") != "regex-syntax-grammar-contract-v1"
        || text(contract, "grammar_id") != GRAMMAR_ID
        || number(contract, "language_version") != 1
        || text(contract, "capability_id") != CAPABILITY_ID
        || text(contract, "bead_id") != BEAD_ID
    {
        return Err("identity or language version drifted".to_owned());
    }

    let decision = object(contract, "decision");
    if decision.get("cutover_eligible").and_then(Value::as_bool) != Some(false)
        || decision.get("unknown_rows").and_then(Value::as_u64) != Some(0)
        || decision
            .get("accepted_unsupported_rows")
            .and_then(Value::as_u64)
            != Some(0)
        || text(&Value::Object(decision.clone()), "incumbent_state") != "KEEP_INCUMBENT"
        || text(&Value::Object(decision.clone()), "candidate_state") != "SPECIFIED_NOT_IMPLEMENTED"
        || text(
            &Value::Object(decision.clone()),
            "on_unknown_or_accepted_unsupported",
        ) != "KEEP_OR_DEFER"
    {
        return Err("fail-closed decision policy drifted".to_owned());
    }
    if !array(contract, "unknown_constructs").is_empty() {
        return Err("unknown constructs must remain empty".to_owned());
    }

    let version = object(contract, "version_contract");
    if version.get("identity").and_then(Value::as_str) != Some(GRAMMAR_ID)
        || version
            .get("wording_is_not_stable")
            .and_then(Value::as_bool)
            != Some(true)
        || version
            .get("normalized_diagnostic_categories_are_stable")
            .and_then(Value::as_bool)
            != Some(true)
        || version
            .get("source_spans_are_half_open_utf8_byte_ranges")
            .and_then(Value::as_bool)
            != Some(true)
        || array(&Value::Object(version.clone()), "immutable_fields").len() != 8
        || array(
            &Value::Object(version.clone()),
            "language_version_bump_required_for",
        )
        .len()
            != 6
    {
        return Err("version contract drifted".to_owned());
    }

    let precedence = array(contract, "precedence");
    if row_ids(precedence, "precedence_id")
        != exact_set(&[
            "RGX-PREC-ATOM",
            "RGX-PREC-REPETITION",
            "RGX-PREC-CONCATENATION",
            "RGX-PREC-ALTERNATION",
        ])
        || precedence
            .iter()
            .map(|row| number(row, "rank"))
            .collect::<BTreeSet<_>>()
            != [1, 2, 3, 4].into_iter().collect()
    {
        return Err("top-level precedence table drifted".to_owned());
    }
    let class_precedence = array(contract, "class_precedence");
    if row_ids(class_precedence, "precedence_id")
        != exact_set(&[
            "RGX-CLASS-PREC-RANGE",
            "RGX-CLASS-PREC-UNION",
            "RGX-CLASS-PREC-SET",
            "RGX-CLASS-PREC-NEGATION",
        ])
        || class_precedence
            .iter()
            .map(|row| number(row, "rank"))
            .collect::<BTreeSet<_>>()
            != [1, 2, 3, 4].into_iter().collect()
    {
        return Err("character-class precedence table drifted".to_owned());
    }

    let flag_defaults: BTreeMap<&str, bool> = array(contract, "flags")
        .iter()
        .map(|row| {
            (
                text(row, "flag"),
                row.get("default")
                    .and_then(Value::as_bool)
                    .expect("flag default"),
            )
        })
        .collect();
    let expected_flags: BTreeMap<&str, bool> = [
        ("i", false),
        ("m", false),
        ("s", false),
        ("R", false),
        ("U", false),
        ("u", true),
        ("x", false),
    ]
    .into_iter()
    .collect();
    if flag_defaults != expected_flags {
        return Err("flag set or defaults drifted".to_owned());
    }

    if row_ids(array(contract, "grammar_productions"), "production_id")
        != exact_set(&[
            "RGX-GRAMMAR-ROOT",
            "RGX-GRAMMAR-ALTERNATION",
            "RGX-GRAMMAR-CONCATENATION",
            "RGX-GRAMMAR-REPETITION",
            "RGX-GRAMMAR-QUANTIFIER",
            "RGX-GRAMMAR-COUNTED",
            "RGX-GRAMMAR-ATOM",
            "RGX-GRAMMAR-GROUP",
            "RGX-GRAMMAR-FLAGS",
            "RGX-GRAMMAR-CLASS",
            "RGX-GRAMMAR-CLASS-EXPRESSION",
            "RGX-GRAMMAR-CLASS-UNION",
            "RGX-GRAMMAR-ESCAPE",
            "RGX-GRAMMAR-ASSERTION",
        ])
    {
        return Err("grammar production set drifted".to_owned());
    }

    let categories = row_ids(array(contract, "diagnostic_categories"), "category_id");
    let constructs = array(contract, "constructs");
    let construct_ids = row_ids(constructs, "construct_id");
    if construct_ids.len() != constructs.len() {
        return Err("construct IDs must be unique".to_owned());
    }
    for construct in constructs {
        match text(construct, "state") {
            "REQUIRED" => {}
            "REJECTED" => {
                if !categories.contains(text(construct, "diagnostic_category")) {
                    return Err(format!(
                        "{} references an unknown diagnostic category",
                        text(construct, "construct_id")
                    ));
                }
            }
            state => {
                return Err(format!(
                    "{} has forbidden state {state}",
                    text(construct, "construct_id")
                ));
            }
        }
    }

    let r1 = parse_repo_json(R1_ARTIFACT_PATH);
    let r1_states: BTreeMap<String, String> = array(&r1, "syntax_corpus")
        .iter()
        .map(|row| {
            (
                text(row, "case_id").to_owned(),
                text(row, "compile_state").to_owned(),
            )
        })
        .collect();
    let mapping = array(contract, "inventory_case_map");
    if mapping.len() != r1_states.len()
        || row_ids(mapping, "case_id") != r1_states.keys().cloned().collect()
    {
        return Err("R1 inventory mapping is missing or has extra rows".to_owned());
    }
    let mut mapped_constructs = BTreeSet::new();
    for row in mapping {
        let case_id = text(row, "case_id");
        if r1_states.get(case_id).map(String::as_str) != Some(text(row, "compile_state")) {
            return Err(format!("{case_id} compile state drifted from R1"));
        }
        let mapped = string_array(row, "construct_ids");
        mapped_constructs.extend(mapped.iter().cloned());
        if mapped.is_empty() || !mapped.is_subset(&construct_ids) {
            return Err(format!(
                "{case_id} has an empty or unknown construct mapping"
            ));
        }
        if text(row, "compile_state") == "ACCEPTED"
            && mapped.iter().all(|id| {
                constructs.iter().any(|construct| {
                    text(construct, "construct_id") == id && text(construct, "state") == "REJECTED"
                })
            })
        {
            return Err(format!("{case_id} maps only to rejected constructs"));
        }
    }
    let required_constructs: BTreeSet<String> = constructs
        .iter()
        .filter(|row| text(row, "state") == "REQUIRED")
        .map(|row| text(row, "construct_id").to_owned())
        .collect();
    if !required_constructs.is_subset(&mapped_constructs) {
        return Err("a required grammar construct has no R1 capability mapping".to_owned());
    }

    let limits: BTreeMap<&str, &Value> = array(contract, "limits")
        .iter()
        .map(|row| (text(row, "limit_id"), row))
        .collect();
    if limits.len() != 7
        || limits["RGX-LIMIT-PATTERN-BYTES"]
            .get("candidate_value")
            .and_then(Value::as_u64)
            != Some(1_048_576)
        || !limits["RGX-LIMIT-PATTERN-BYTES"]
            .get("incumbent_value")
            .is_some_and(Value::is_null)
        || limits["RGX-LIMIT-TOKENS"]
            .get("candidate_value")
            .and_then(Value::as_u64)
            != Some(1_048_576)
        || limits["RGX-LIMIT-AST-NODES"]
            .get("candidate_value")
            .and_then(Value::as_u64)
            != Some(1_048_576)
        || limits["RGX-LIMIT-NESTING"]
            .get("incumbent_value")
            .and_then(Value::as_u64)
            != Some(250)
        || limits["RGX-LIMIT-NESTING"]
            .get("candidate_value")
            .and_then(Value::as_u64)
            != Some(250)
        || limits["RGX-LIMIT-REPETITION-COUNT"]
            .get("candidate_value")
            .and_then(Value::as_u64)
            != Some(u32::MAX.into())
        || limits["RGX-LIMIT-COMPILED-NFA-BYTES"]
            .get("candidate_value")
            .and_then(Value::as_u64)
            != Some(10 * 1024 * 1024)
        || limits["RGX-LIMIT-HYBRID-CACHE-BYTES"]
            .get("candidate_value")
            .and_then(Value::as_u64)
            != Some(2 * 1024 * 1024)
    {
        return Err("frozen limits changed".to_owned());
    }
    for id in [
        "RGX-LIMIT-PATTERN-BYTES",
        "RGX-LIMIT-TOKENS",
        "RGX-LIMIT-AST-NODES",
    ] {
        if limits[id].get("parity_state").and_then(Value::as_str)
            != Some("CUTOVER_BLOCKER_UNTIL_POLICY_AND_CORPUS_PROVE_ACCEPTABLE")
        {
            return Err(format!("{id} lost its cutover-blocker state"));
        }
    }

    let goldens = array(contract, "golden_cases");
    if goldens.len() != 20 || row_ids(goldens, "case_id").len() != goldens.len() {
        return Err("golden corpus must retain 20 unique cases".to_owned());
    }
    let mut golden_source_ids = row_ids(array(contract, "upstream_specifications"), "source_id");
    golden_source_ids.insert("R1-INVENTORY".to_owned());
    for row in goldens {
        let pattern = text(row, "pattern");
        if !golden_source_ids.contains(text(row, "source_id")) {
            return Err(format!(
                "{} has an unknown independent source",
                text(row, "case_id")
            ));
        }
        match text(row, "expected_state") {
            "ACCEPTED" => {
                if text(row, "expected_ast").is_empty() {
                    return Err(format!("{} has no normalized AST", text(row, "case_id")));
                }
                let span = object(row, "ast_span");
                if span.get("start").and_then(Value::as_u64) != Some(0)
                    || span.get("end").and_then(Value::as_u64) != Some(pattern.len() as u64)
                {
                    return Err(format!("{} AST span is not complete", text(row, "case_id")));
                }
            }
            "REJECTED" => {
                if !categories.contains(text(row, "diagnostic_category"))
                    || text(row, "error_contains").is_empty()
                {
                    return Err(format!(
                        "{} has an unknown or empty diagnostic",
                        text(row, "case_id")
                    ));
                }
                let span = object(row, "error_span");
                let start = span
                    .get("start")
                    .and_then(Value::as_u64)
                    .expect("error span start") as usize;
                let end = span
                    .get("end")
                    .and_then(Value::as_u64)
                    .expect("error span end") as usize;
                if start > end
                    || end > pattern.len()
                    || !pattern.is_char_boundary(start)
                    || !pattern.is_char_boundary(end)
                {
                    return Err(format!(
                        "{} has an invalid error span",
                        text(row, "case_id")
                    ));
                }
            }
            state => return Err(format!("golden case has unsupported state {state}")),
        }
    }
    Ok(())
}

#[test]
fn grammar_contract_is_complete_versioned_and_zero_unknown() {
    let contract = artifact();
    validate_contract(&contract).unwrap_or_else(|error| panic!("{error}"));
}

#[test]
fn source_pins_and_resolved_upstream_versions_are_exact() {
    let contract = artifact();
    for pin in array(&contract, "source_pins") {
        let path = text(pin, "path");
        let bytes = read_repo_bytes(path);
        assert_eq!(
            hex::encode(Sha256::digest(&bytes)),
            text(pin, "sha256"),
            "{path} source pin drifted"
        );
        assert_eq!(
            pin.get("line_count").and_then(Value::as_u64),
            Some(read_repo_file(path).lines().count() as u64),
            "{path} line count drifted"
        );
    }

    let lock = read_repo_file("Cargo.lock");
    for marker in [
        "name = \"regex\"\nversion = \"1.13.1\"",
        "checksum = \"f020237b6c8eed93db2e2cb53c00c60a8e1bc73da7d073199a1180401450218d\"",
        "name = \"regex-syntax\"\nversion = \"0.8.11\"",
        "checksum = \"d6f6ff9a378485b298a5286656da665ba74413d36db0979633275d2e708145d4\"",
    ] {
        assert!(lock.contains(marker), "lockfile lost {marker}");
    }

    let source_ids = row_ids(array(&contract, "upstream_specifications"), "source_id");
    assert_eq!(
        source_ids,
        exact_set(&["REGEX-SPEC-1", "REGEX-SPEC-2", "REGEX-SPEC-3"])
    );
}

#[test]
fn golden_corpus_matches_incumbent_compile_and_match_behavior() {
    let contract = artifact();
    for row in array(&contract, "golden_cases") {
        let case_id = text(row, "case_id");
        let pattern = text(row, "pattern");
        match text(row, "expected_state") {
            "ACCEPTED" => {
                let compiled = IncumbentRegex::new(pattern)
                    .unwrap_or_else(|error| panic!("{case_id} unexpectedly rejected: {error}"));
                let public = PrivacyConfig::new().try_with_pii_pattern(pattern);
                assert!(public.is_ok(), "{case_id} public builder rejected");

                let actual = compiled.find(text(row, "haystack")).map(|found| {
                    (
                        u64::try_from(found.start()).expect("match start"),
                        u64::try_from(found.end()).expect("match end"),
                    )
                });
                let expected = row.get("match_span").and_then(|span| {
                    span.as_object().map(|span| {
                        (
                            span.get("start")
                                .and_then(Value::as_u64)
                                .expect("match start"),
                            span.get("end").and_then(Value::as_u64).expect("match end"),
                        )
                    })
                });
                assert_eq!(actual, expected, "{case_id} match span drifted");
            }
            "REJECTED" => {
                let error = IncumbentRegex::new(pattern)
                    .err()
                    .unwrap_or_else(|| panic!("{case_id} unexpectedly compiled"))
                    .to_string();
                assert!(
                    error
                        .to_ascii_lowercase()
                        .contains(&text(row, "error_contains").to_ascii_lowercase()),
                    "{case_id} error `{error}` lost `{}`",
                    text(row, "error_contains")
                );
                assert!(
                    PrivacyConfig::new().try_with_pii_pattern(pattern).is_err(),
                    "{case_id} public builder unexpectedly accepted"
                );
            }
            state => panic!("{case_id} has unsupported state {state}"),
        }
    }
}

#[test]
fn limits_version_and_inventory_coverage_fail_closed_under_mutation() {
    let contract = artifact();

    let mut changed_version = contract.clone();
    changed_version["language_version"] = Value::from(2);
    assert!(
        validate_contract(&changed_version)
            .expect_err("language version mutation must fail")
            .contains("identity or language version")
    );

    let mut changed_limit = contract.clone();
    changed_limit["limits"][0]["candidate_value"] = Value::from(65_536);
    assert!(
        validate_contract(&changed_limit)
            .expect_err("limit mutation must fail")
            .contains("frozen limits")
    );

    let mut missing_inventory_row = contract.clone();
    missing_inventory_row["inventory_case_map"]
        .as_array_mut()
        .expect("inventory map")
        .pop();
    assert!(
        validate_contract(&missing_inventory_row)
            .expect_err("missing inventory row must fail")
            .contains("R1 inventory mapping")
    );

    let mut unknown = contract;
    unknown["unknown_constructs"]
        .as_array_mut()
        .expect("unknown constructs")
        .push(Value::from("RGX-CONSTRUCT-UNKNOWN"));
    assert!(
        validate_contract(&unknown)
            .expect_err("unknown construct must fail")
            .contains("unknown constructs")
    );
}

#[test]
fn operator_document_retains_authority_handoff_and_no_claims() {
    let doc = read_repo_file(DOC_PATH);
    let begin = doc
        .find("<!-- BEGIN REGEX SYNTAX GRAMMAR CONTRACT -->")
        .expect("document begin marker");
    let end = doc
        .find("<!-- END REGEX SYNTAX GRAMMAR CONTRACT -->")
        .expect("document end marker");
    assert!(begin < end);

    for marker in [
        "`ASUP-REGEX-SYNTAX-V1`",
        "`CAP-REGEX-PRIVACY`",
        "`KEEP_INCUMBENT`",
        "`SPECIFIED_NOT_IMPLEMENTED`",
        "`KEEP_OR_DEFER`",
        "`RGX-DIAG-*`",
        "`CUTOVER_BLOCKER_UNTIL_POLICY_AND_CORPUS_PROVE_ACCEPTABLE`",
        "`asupersync-5z2scg.8.3.1.2`",
        "`regex_adversarial_limits`",
        "No local Cargo fallback",
        "does not implement a lexer, parser, compiler, matcher",
    ] {
        assert!(doc.contains(marker), "operator document lost {marker}");
    }
}
