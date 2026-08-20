//! Fail-closed contract for the R3.1 regex syntax terminal receipt.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::PathBuf;

use regex::Regex as IncumbentRegex;
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

const RECEIPT_PATH: &str = "artifacts/regex_syntax_terminal_receipt_v1.json";
const GRAMMAR_PATH: &str = "artifacts/regex_syntax_grammar_contract_v1.json";
const INVENTORY_PATH: &str = "artifacts/regex_privacy_capability_inventory_v1.json";
const SOURCE_PATH: &str = "src/observability/regex_syntax.rs";
const DOC_PATH: &str = "docs/regex_syntax_terminal_receipt.md";
const BEAD_ID: &str = "asupersync-5z2scg.8.3.1.4";
const CAPABILITY_ID: &str = "CAP-REGEX-PRIVACY";
const GRAMMAR_ID: &str = "ASUP-REGEX-SYNTAX-V1";

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

fn object<'a>(value: &'a Value, key: &str) -> Result<&'a Map<String, Value>, String> {
    value
        .get(key)
        .and_then(Value::as_object)
        .ok_or_else(|| format!("{key} must be an object"))
}

fn array<'a>(value: &'a Value, key: &str) -> Result<&'a Vec<Value>, String> {
    value
        .get(key)
        .and_then(Value::as_array)
        .ok_or_else(|| format!("{key} must be an array"))
}

fn text<'a>(value: &'a Value, key: &str) -> Result<&'a str, String> {
    value
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("{key} must be text"))
}

fn number(value: &Value, key: &str) -> Result<u64, String> {
    value
        .get(key)
        .and_then(Value::as_u64)
        .ok_or_else(|| format!("{key} must be an unsigned integer"))
}

fn boolean(value: &Value, key: &str) -> Result<bool, String> {
    value
        .get(key)
        .and_then(Value::as_bool)
        .ok_or_else(|| format!("{key} must be a boolean"))
}

fn object_value(value: &Value, key: &str) -> Result<Value, String> {
    Ok(Value::Object(object(value, key)?.clone()))
}

fn row_ids(rows: &[Value], key: &str) -> Result<BTreeSet<String>, String> {
    rows.iter()
        .map(|row| text(row, key).map(str::to_owned))
        .collect()
}

fn exact_set(values: &[&str]) -> BTreeSet<String> {
    values.iter().map(|value| (*value).to_owned()).collect()
}

fn sha256(relative: &str) -> String {
    hex::encode(Sha256::digest(read_repo_bytes(relative)))
}

fn validate_receipt(receipt: &Value, grammar: &Value, inventory: &Value) -> Result<(), String> {
    if number(receipt, "schema_version")? != 1
        || text(receipt, "artifact_id")? != "regex-syntax-terminal-receipt-v1"
        || text(receipt, "program_id")? != "dependency-sovereignty"
        || text(receipt, "bead_id")? != BEAD_ID
        || text(receipt, "capability_id")? != CAPABILITY_ID
        || text(receipt, "grammar_id")? != GRAMMAR_ID
        || number(receipt, "language_version")? != 1
    {
        return Err("terminal receipt identity drifted".to_owned());
    }
    if text(grammar, "grammar_id")? != GRAMMAR_ID
        || number(grammar, "language_version")? != 1
        || text(inventory, "capability_id")? != CAPABILITY_ID
    {
        return Err("upstream grammar or inventory identity drifted".to_owned());
    }

    let revisions = object_value(receipt, "source_revisions")?;
    let expected_revisions = [
        ("r1_inventory", "8b399fa72"),
        ("grammar_contract", "4074a2746"),
        ("lexer", "582da577c"),
        ("parser", "9056ef793"),
        (
            "terminal_repairs",
            "432be7270481c5439db00f79910465a269512266",
        ),
    ];
    for (key, expected) in expected_revisions {
        if text(&revisions, key)? != expected {
            return Err(format!("source revision {key} drifted"));
        }
    }

    let digest_rows = array(receipt, "source_digests")?;
    if digest_rows.len() != 3 {
        return Err("source digest row count drifted".to_owned());
    }
    let digest_map = digest_rows
        .iter()
        .map(|row| {
            Ok((
                text(row, "path")?.to_owned(),
                text(row, "sha256")?.to_owned(),
            ))
        })
        .collect::<Result<BTreeMap<_, _>, String>>()?;
    let expected_historical_digests = BTreeMap::from([
        (
            SOURCE_PATH.to_owned(),
            "25ba1e6b24ce2741c39b831c580dda716a6c0d4113470c159382fb2a842cc98e".to_owned(),
        ),
        (
            GRAMMAR_PATH.to_owned(),
            "e15615c0d5e4df04c8938e7089c3cad817b1081c9b8e96dacd5111696fb0c966".to_owned(),
        ),
        (
            INVENTORY_PATH.to_owned(),
            "dfc6b686658865b03839bb6c187fe48f189808ef1c33e227c7ad5afab8939e16".to_owned(),
        ),
    ]);
    if digest_map != expected_historical_digests {
        return Err("historical source digest receipt drifted".to_owned());
    }
    for path in [SOURCE_PATH, GRAMMAR_PATH, INVENTORY_PATH] {
        if !repo_path(path).is_file() {
            return Err(format!(
                "historically pinned source path is missing: {path}"
            ));
        }
    }
    if sha256(SOURCE_PATH) != digest_map[SOURCE_PATH] {
        return Err("candidate syntax source drifted".to_owned());
    }

    let oracle = object_value(receipt, "oracle")?;
    if text(&oracle, "incumbent_package")? != "regex@1.13.1"
        || text(&oracle, "structural_reference_package")? != "regex-syntax@0.8.11"
        || !boolean(&oracle, "quarantined")?
        || !boolean(&oracle, "wording_is_not_compared")?
        || text(&oracle, "oracle_expiry_utc")? != "2026-10-23T00:00:00Z"
        || array(&oracle, "invalidate_earlier_on")?.len() != 4
    {
        return Err("oracle pin, quarantine, or expiry drifted".to_owned());
    }

    let decision = object_value(receipt, "decision")?;
    if !boolean(&decision, "terminal_receipt_complete")?
        || text(&decision, "syntax_disposition")? != "KEEP_INCUMBENT_DEFER"
        || text(&decision, "incumbent_state")? != "KEEP_INCUMBENT"
        || text(&decision, "candidate_state")? != "BOUNDED_PARSER_WITH_ACCEPTED_SYNTAX_COMPLETE"
        || boolean(&decision, "cutover_eligible")?
        || boolean(&decision, "dependency_removal_authorized")?
        || number(&decision, "same_rows")? != 31
        || number(&decision, "better_rows")? != 0
        || number(&decision, "defer_rows")? != 0
        || number(&decision, "unknown_rows")? != 0
        || number(&decision, "unresolved_high_findings")? != 0
        || number(&decision, "resolved_by_fail_closed_disposition")? != 1
        || text(&decision, "on_missing_row_or_new_divergence")? != "KEEP_INCUMBENT_DEFER"
    {
        return Err("fail-closed terminal decision drifted".to_owned());
    }

    let receipt_rows = array(receipt, "row_results")?;
    let inventory_rows = array(inventory, "syntax_corpus")?;
    let grammar_rows = array(grammar, "inventory_case_map")?;
    let expected_ids = row_ids(inventory_rows, "case_id")?;
    if expected_ids.len() != 31
        || row_ids(grammar_rows, "case_id")? != expected_ids
        || row_ids(receipt_rows, "case_id")? != expected_ids
        || receipt_rows.len() != expected_ids.len()
    {
        return Err("syntax row coverage is not an exact 31-row join".to_owned());
    }
    let deferred = receipt_rows
        .iter()
        .filter(|row| text(row, "parity").is_ok_and(|parity| parity == "DEFER"))
        .map(|row| text(row, "case_id").map(str::to_owned))
        .collect::<Result<BTreeSet<_>, _>>()?;
    let same = receipt_rows
        .iter()
        .filter(|row| text(row, "parity").is_ok_and(|parity| parity == "SAME"))
        .count();
    if !deferred.is_empty() || same != 31 {
        return Err("row-level SAME/DEFER disposition drifted".to_owned());
    }
    for row in receipt_rows {
        if !matches!(text(row, "parity")?, "SAME" | "BETTER" | "DEFER") {
            return Err("row contains UNKNOWN or unsupported parity value".to_owned());
        }
        if text(row, "case_id")? == "RGX-SYN-011"
            && text(row, "resolution_id")? != "RGX-R351-X-GRAMMAR-AWARE-ELISION"
        {
            return Err("verbose-mode row lost its R3.5.1 resolution receipt".to_owned());
        }
    }

    let diagnostics = array(receipt, "diagnostic_results")?;
    if diagnostics.len() != 8
        || row_ids(diagnostics, "case_id")?
            != exact_set(&[
                "RGX-GOLDEN-013",
                "RGX-GOLDEN-014",
                "RGX-GOLDEN-015",
                "RGX-GOLDEN-016",
                "RGX-GOLDEN-017",
                "RGX-GOLDEN-018",
                "RGX-GOLDEN-019",
                "RGX-GOLDEN-020",
            ])
    {
        return Err("diagnostic golden coverage drifted".to_owned());
    }
    let golden_map = array(grammar, "golden_cases")?
        .iter()
        .filter(|row| row.get("expected_state").and_then(Value::as_str) == Some("REJECTED"))
        .map(|row| Ok((text(row, "case_id")?.to_owned(), row)))
        .collect::<Result<BTreeMap<_, _>, String>>()?;
    for row in diagnostics {
        let case_id = text(row, "case_id")?;
        let golden = golden_map
            .get(case_id)
            .ok_or_else(|| format!("missing rejected golden {case_id}"))?;
        let span = object_value(golden, "error_span")?;
        let expected_span = [number(&span, "start")?, number(&span, "end")?];
        let actual_span = array(row, "byte_span")?
            .iter()
            .map(|value| {
                value
                    .as_u64()
                    .ok_or_else(|| "byte_span entries must be integers".to_owned())
            })
            .collect::<Result<Vec<_>, _>>()?;
        if text(row, "category")? != text(golden, "diagnostic_category")?
            || actual_span != expected_span
            || text(row, "parity")? != "SAME"
        {
            return Err(format!("diagnostic category/span drifted for {case_id}"));
        }
    }

    let limits = array(receipt, "limits")?;
    let grammar_limits = array(grammar, "limits")?;
    if limits.len() != 5 {
        return Err("terminal limit row count drifted".to_owned());
    }
    let grammar_limit_values = grammar_limits
        .iter()
        .filter_map(|row| {
            Some((
                text(row, "limit_id").ok()?.to_owned(),
                row.get("candidate_value")?.as_u64()?,
            ))
        })
        .collect::<BTreeMap<_, _>>();
    for row in limits {
        let limit_id = text(row, "limit_id")?;
        if grammar_limit_values.get(limit_id) != Some(&number(row, "candidate_value")?) {
            return Err(format!("limit value drifted for {limit_id}"));
        }
        if !matches!(text(row, "parity")?, "SAME" | "DEFER_CANDIDATE_ONLY_POLICY") {
            return Err(format!("invalid limit disposition for {limit_id}"));
        }
    }

    let evidence = object_value(receipt, "evidence_summary")?;
    for (key, expected) in [
        ("inventory_rows", 31),
        ("golden_cases", 20),
        ("accepted_goldens", 12),
        ("diagnostic_goldens", 8),
        ("adversarial_compile_cases", 62),
        ("retained_lexer_regressions", 16),
        ("retained_parser_regressions", 23),
        ("property_cases_per_lane", 256),
        ("property_lanes", 4),
        ("generated_property_cases", 1024),
        ("focused_tests", 36),
    ] {
        if number(&evidence, key)? != expected {
            return Err(format!("evidence count {key} drifted"));
        }
    }
    if boolean(&evidence, "panic_observed")?
        || boolean(&evidence, "unbounded_ast_expansion_observed")?
        || boolean(&evidence, "source_text_in_diagnostics_observed")?
    {
        return Err("evidence summary reports an inadmissible finding".to_owned());
    }

    let repairs = array(receipt, "repair_receipts")?;
    if row_ids(repairs, "repair_id")?
        != exact_set(&[
            "RGX-REPAIR-DIRECT-NESTED-REPETITION",
            "RGX-REPAIR-MISSING-REPETITION-SPAN",
            "RGX-REPAIR-EMPTY-CLASS-SET-OPERANDS",
        ])
        || repairs.iter().any(|row| match text(row, "result") {
            Ok("SAME") => false,
            Ok(_) | Err(_) => true,
        })
    {
        return Err("repair receipt coverage drifted".to_owned());
    }
    for row in repairs {
        if array(row, "minimized_inputs")?.is_empty() || text(row, "evidence_test")?.is_empty() {
            return Err("repair receipt lost minimized input or evidence test".to_owned());
        }
    }

    let divergences = array(receipt, "divergence_register")?;
    if row_ids(divergences, "blocker_id")?
        != exact_set(&[
            "RGX-GAP-X-WHITESPACE",
            "RGX-GAP-DUPLICATE-CAPTURE-NAME",
            "RGX-GAP-UNICODE-PROPERTY-VALIDATION",
        ])
    {
        return Err("divergence register drifted".to_owned());
    }
    for row in divergences {
        let blocker_id = text(row, "blocker_id")?;
        let disposition_is_exact = match blocker_id {
            "RGX-GAP-X-WHITESPACE" | "RGX-GAP-DUPLICATE-CAPTURE-NAME" => {
                text(row, "severity")? == "RESOLVED" && text(row, "disposition")? == "SAME_R3_5_1"
            }
            "RGX-GAP-UNICODE-PROPERTY-VALIDATION" => {
                text(row, "severity")? == "HIGH_CUTOVER_BLOCKER"
                    && text(row, "disposition")? == "DEFER_KEEP_INCUMBENT"
            }
            _ => false,
        };
        if !disposition_is_exact
            || array(row, "minimized_inputs")?.is_empty()
            || text(row, "owner_bead")?.is_empty()
            || text(row, "candidate_observation")?.is_empty()
            || text(row, "incumbent_observation")?.is_empty()
        {
            return Err("divergence or resolved-gap receipt lost required fields".to_owned());
        }
    }

    let replay = object_value(receipt, "seeds_and_replay")?;
    if text(&replay, "lexer_seed")? != "0x5A2C0312"
        || text(&replay, "parser_seed")? != "0x5A2C0313"
        || number(&replay, "proptest_cases_per_lane")? != 256
        || !text(&replay, "focused_source_command")?.contains("RCH_REQUIRE_REMOTE=1")
        || !text(&replay, "terminal_contract_command")?.contains("RCH_REQUIRE_REMOTE=1")
    {
        return Err("seed or remote replay contract drifted".to_owned());
    }

    let redaction = object_value(receipt, "redaction")?;
    if boolean(&redaction, "source_text_rendered_by_candidate_errors")?
        || text(&redaction, "canary")? != "private-source-canary"
        || boolean(&redaction, "canary_observed_in_rendered_error")?
        || array(&redaction, "stable_display_fields")?.len() != 4
    {
        return Err("redaction contract drifted".to_owned());
    }
    let lifecycle = object_value(receipt, "lifecycle_scope")?;
    if number(&lifecycle, "tasks")? != 0
        || number(&lifecycle, "obligations")? != 0
        || number(&lifecycle, "io_effects")? != 0
        || boolean(&lifecycle, "cancellation_applicable")?
    {
        return Err("pure parser lifecycle scope drifted".to_owned());
    }

    let no_claims = array(receipt, "no_claim_boundaries")?
        .iter()
        .map(|value| {
            value
                .as_str()
                .ok_or_else(|| "no-claim entries must be text".to_owned())
        })
        .collect::<Result<Vec<_>, _>>()?;
    for required in [
        "does not authorize removing regex or regex-syntax",
        "does not prove Unicode/property/byte-mode parity",
        "does not prove compiler, matcher, capture, replacement, cache, or privacy behavior",
        "does not prove performance improvement or no regression",
        "does not prove broad workspace health or release readiness",
        "does not claim the canonical dependency-sovereignty E2E has run",
        "does not authorize local Cargo fallback",
    ] {
        if !no_claims.contains(&required) {
            return Err(format!("missing no-claim boundary: {required}"));
        }
    }
    Ok(())
}

#[test]
fn terminal_receipt_is_complete_digest_bound_and_fail_closed() {
    let receipt = parse_repo_json(RECEIPT_PATH);
    let grammar = parse_repo_json(GRAMMAR_PATH);
    let inventory = parse_repo_json(INVENTORY_PATH);
    validate_receipt(&receipt, &grammar, &inventory).unwrap_or_else(|error| panic!("{error}"));
}

#[test]
fn terminal_receipt_rejects_overclaim_missing_rows_and_hidden_findings() {
    let receipt = parse_repo_json(RECEIPT_PATH);
    let grammar = parse_repo_json(GRAMMAR_PATH);
    let inventory = parse_repo_json(INVENTORY_PATH);

    let mut overclaim = receipt.clone();
    overclaim["decision"]["cutover_eligible"] = Value::Bool(true);
    assert!(validate_receipt(&overclaim, &grammar, &inventory).is_err());

    let mut missing_row = receipt.clone();
    missing_row["row_results"]
        .as_array_mut()
        .expect("row_results")
        .pop();
    assert!(validate_receipt(&missing_row, &grammar, &inventory).is_err());

    let mut hidden_finding = receipt.clone();
    hidden_finding["decision"]["unresolved_high_findings"] = Value::from(1);
    assert!(validate_receipt(&hidden_finding, &grammar, &inventory).is_err());

    let mut stale_oracle = receipt.clone();
    stale_oracle["oracle"]["oracle_expiry_utc"] = Value::String("2026-07-24T00:00:00Z".to_owned());
    assert!(validate_receipt(&stale_oracle, &grammar, &inventory).is_err());
}

#[test]
fn quarantined_incumbent_divergence_inputs_replay_at_pinned_resolution() {
    for pattern in [
        "(?x)a{ 2 , 3 }",
        "(?x)\\x { 53 }",
        "(?x)\\u { 53 }",
        "(?x)\\p { Greek }",
    ] {
        assert!(
            IncumbentRegex::new(pattern).is_ok(),
            "incumbent should accept {pattern:?}"
        );
    }
    for pattern in [
        "(?P<name>a)|(?P<name>b)",
        "\\p{DefinitelyNotAProperty}",
        "(?-u:\\pL)",
        "(?-u:\\xFF)",
    ] {
        assert!(
            IncumbentRegex::new(pattern).is_err(),
            "incumbent should reject {pattern:?}"
        );
    }
}

#[test]
fn operator_doc_and_candidate_source_preserve_receipt_markers() {
    let doc = read_repo_file(DOC_PATH);
    for required in [
        "<!-- BEGIN REGEX SYNTAX TERMINAL RECEIPT -->",
        "`KEEP_INCUMBENT_DEFER`",
        "`RGX-GAP-X-WHITESPACE`",
        "`RGX-GAP-DUPLICATE-CAPTURE-NAME`",
        "`RGX-GAP-UNICODE-PROPERTY-VALIDATION`",
        "2026-10-23T00:00:00Z",
        "RCH_REQUIRE_REMOTE=1 rch exec --",
        "No local Cargo fallback is approved.",
        "does not authorize removing `regex` or `regex-syntax`",
        "<!-- END REGEX SYNTAX TERMINAL RECEIPT -->",
    ] {
        assert!(doc.contains(required), "operator doc missing {required:?}");
    }

    let source = read_repo_file(SOURCE_PATH);
    for required in [
        "private-source-canary",
        "directly_nested_repetition_matches_incumbent_syntax_and_stays_bounded",
        "class_set_operators_preserve_incumbent_empty_operands",
        "quarantined_incumbent_and_candidate_compile_states_match_adversarial_corpus",
        "extended_mode_elides_only_grammar_ignored_text_and_preserves_spans",
        "duplicate_capture_names_fail_with_a_stable_secret_safe_code",
        "frozen_invalid_goldens_match_diagnostic_category_and_span",
    ] {
        assert!(
            source.contains(required),
            "candidate source missing {required:?}"
        );
    }
}
