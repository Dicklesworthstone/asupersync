//! Fail-closed corpus contract for the four built-in privacy detectors.
//!
//! Bead: asupersync-5z2scg.8.2.1
//! Fixture: artifacts/regex_built_in_detector_corpus_v1.json
//!
//! The vectors are independently authored and the incumbent is used only as
//! a differential oracle. This test implements no scanner, production
//! dispatch, performance claim, dependency exit, or cutover.

#![cfg(feature = "metrics")]
#![allow(missing_docs)]

use asupersync::observability::otel::PrivacyConfig;
use regex::Regex;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

const ARTIFACT_PATH: &str = "artifacts/regex_built_in_detector_corpus_v1.json";
const DOC_PATH: &str = "docs/regex_built_in_detector_corpus.md";
const SOURCE_PATH: &str = "src/observability/otel.rs";
const REGISTRY_PATH: &str = "artifacts/dependency_capability_registry_v1.json";
const BASELINE_PATH: &str = "artifacts/dependency_capability_baseline_v1.json";
const R1_ARTIFACT_PATH: &str = "artifacts/regex_privacy_capability_inventory_v1.json";
const R1_CORPUS_REFERENCE: &str =
    "artifacts/regex_privacy_capability_inventory_v1.json#built_in_detector_corpus";
const IGNORE_PATH: &str = ".gitignore";
const ARTIFACT_ID: &str = "regex-built-in-detector-corpus-v1";
const PROGRAM_ID: &str = "asupersync-ir2uf0";
const BEAD_ID: &str = "asupersync-5z2scg.8.2.1";
const CAPABILITY_ID: &str = "CAP-REGEX-PRIVACY";
const SOURCE_REVISION: &str = "3b222630d3814ea0bd254709d10e14953f90441e";
const AUTHORITY_REVISION: &str = "5f208e04f24d8addaa051c9bf7465f7b398848fe";
const BASELINE_AUTHORITY_REVISION: &str = "7390d33f4ac297cd28138c8e1ece38f60b278660";
const R1_EVIDENCE_REVISION: &str = "8b399fa722e47e55950164655dd18276d9fc85fc";
const PROVENANCE_REFRESH_ID: &str = "RGX-R2-SOURCE-PIN-REFRESH-2026-08-06";
const BASELINE_CURRENT_REVISION: &str = "612a82a546634ba1de2d06fe6e429bf85516a475";
const BASELINE_PREVIOUS_SHA256: &str =
    "88575b016105828ce8c1792492355fd34e8a3687ef6be2509e0412dee949cda8";
const BASELINE_CURRENT_SHA256: &str =
    "7a94026143e7b81f268a3e3a06d3f7177178a5193dfee1cbd31d45dc34363f0e";
const REGEX_CAPABILITY_ROW_SHA256: &str =
    "5053806ac9a546ea240a6efc0190969da549f31ed03cf17e4b7b40f45adedc5b";
const LAB_CAPABILITY_ROW_SHA256: &str =
    "335025c213cd9a79c1d95dbe4b8fae77787478e6cff42bf141a265f597fd348b";
const SOURCE_PIN_PATHS_SHA256: &str =
    "b5ba6ff6a6eb152e0c3bb263205e8a7d9f9a58fbbb27ec13fd276eb909d9552a";
const CLAIMS_PROJECTION_SHA256: &str =
    "9577ff87a52566038d9ab07be667f5c91fde5c3b208b0bd6e1d070aec28ff8df";
const DOC_BEGIN: &str = "<!-- BEGIN REGEX BUILT-IN DETECTOR CORPUS -->";
const DOC_END: &str = "<!-- END REGEX BUILT-IN DETECTOR CORPUS -->";

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn read_repo_bytes(path: &str) -> Vec<u8> {
    std::fs::read(repo_root().join(path))
        .unwrap_or_else(|error| panic!("failed to read {path}: {error}"))
}

fn read_repo_file(path: &str) -> String {
    String::from_utf8(read_repo_bytes(path))
        .unwrap_or_else(|error| panic!("{path} must be UTF-8: {error}"))
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

fn number(value: &Value, key: &str) -> u64 {
    value
        .get(key)
        .and_then(Value::as_u64)
        .unwrap_or_else(|| panic!("{key} must be an unsigned integer"))
}

fn flag(value: &Value, key: &str) -> bool {
    value
        .get(key)
        .and_then(Value::as_bool)
        .unwrap_or_else(|| panic!("{key} must be a boolean"))
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

fn row_ids(rows: &[Value], key: &str) -> BTreeSet<String> {
    rows.iter().map(|row| text(row, key).to_owned()).collect()
}

fn find_row<'a>(rows: &'a [Value], key: &str, expected: &str) -> &'a Value {
    rows.iter()
        .find(|row| row.get(key).and_then(Value::as_str) == Some(expected))
        .unwrap_or_else(|| panic!("missing {key}={expected}"))
}

fn contains_unknown(value: &Value) -> bool {
    match value {
        Value::String(value) => value.contains("UNKNOWN"),
        Value::Array(values) => values.iter().any(contains_unknown),
        Value::Object(values) => values.values().any(contains_unknown),
        Value::Null | Value::Bool(_) | Value::Number(_) => false,
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    const LOWER: &[u8; 16] = b"0123456789abcdef";
    let digest = Sha256::digest(bytes);
    let mut encoded = String::with_capacity(digest.len() * 2);
    for byte in digest {
        encoded.push(char::from(LOWER[usize::from(byte >> 4)]));
        encoded.push(char::from(LOWER[usize::from(byte & 0x0f)]));
    }
    encoded
}

fn write_canonical_json(value: &Value, output: &mut String) {
    match value {
        Value::Null => output.push_str("null"),
        Value::Bool(value) => output.push_str(if *value { "true" } else { "false" }),
        Value::Number(value) => output.push_str(&value.to_string()),
        Value::String(value) => output.push_str(
            &serde_json::to_string(value).expect("JSON string serialization must succeed"),
        ),
        Value::Array(values) => {
            output.push('[');
            for (index, child) in values.iter().enumerate() {
                if index != 0 {
                    output.push(',');
                }
                write_canonical_json(child, output);
            }
            output.push(']');
        }
        Value::Object(values) => {
            output.push('{');
            let mut keys: Vec<_> = values.keys().collect();
            keys.sort_unstable();
            for (index, key) in keys.into_iter().enumerate() {
                if index != 0 {
                    output.push(',');
                }
                output.push_str(
                    &serde_json::to_string(key).expect("JSON key serialization must succeed"),
                );
                output.push(':');
                write_canonical_json(
                    values.get(key).expect("canonical JSON key must exist"),
                    output,
                );
            }
            output.push('}');
        }
    }
}

fn claims_projection(corpus: &Value) -> Value {
    serde_json::json!({
        "authority": corpus["authority"].clone(),
        "policy": corpus["policy"].clone(),
        "source_pin_scope": corpus["source_pin_scope"].clone(),
        "source_pins": corpus["source_pins"].clone(),
        "r1_case_crosswalk": corpus["r1_case_crosswalk"].clone(),
        "provenance": corpus["provenance"].clone(),
        "capabilities": corpus["capabilities"].clone(),
        "detectors": corpus["detectors"].clone(),
        "dispatch_allowset": corpus["dispatch_allowset"].clone(),
        "required_coverage_tags_per_detector":
            corpus["required_coverage_tags_per_detector"].clone(),
        "detector_vectors": corpus["detector_vectors"].clone(),
        "pipeline_vectors": corpus["pipeline_vectors"].clone(),
        "dispatch_negative_fixtures": corpus["dispatch_negative_fixtures"].clone(),
        "coverage_matrix": corpus["coverage_matrix"].clone(),
        "downstream_handoff": corpus["downstream_handoff"].clone(),
        "rollback_triggers": corpus["rollback_triggers"].clone(),
        "no_claim_boundaries": corpus["no_claim_boundaries"].clone(),
    })
}

fn canonical_sha256(value: &Value) -> String {
    let mut canonical = String::new();
    write_canonical_json(value, &mut canonical);
    sha256_hex(canonical.as_bytes())
}

fn materialize_input(row: &Value) -> String {
    match (
        row.get("input").and_then(Value::as_str),
        row.get("input_recipe").and_then(Value::as_object),
    ) {
        (Some(input), None) => input.to_owned(),
        (None, Some(recipe)) => {
            let prefix = recipe
                .get("prefix")
                .and_then(Value::as_str)
                .expect("recipe prefix");
            let repeated = recipe
                .get("repeat")
                .and_then(Value::as_str)
                .expect("recipe repeat");
            let count = recipe
                .get("repeat_count")
                .and_then(Value::as_u64)
                .and_then(|value| usize::try_from(value).ok())
                .expect("recipe repeat_count must fit usize");
            let suffix = recipe
                .get("suffix")
                .and_then(Value::as_str)
                .expect("recipe suffix");
            format!("{prefix}{}{suffix}", repeated.repeat(count))
        }
        _ => panic!(
            "{} must define exactly one input form",
            text(row, "case_id")
        ),
    }
}

fn independent_luhn(candidate: &str) -> bool {
    let digits: Vec<u32> = candidate.chars().filter_map(|ch| ch.to_digit(10)).collect();
    if !(13..=19).contains(&digits.len()) {
        return false;
    }
    let sum: u32 = digits
        .iter()
        .rev()
        .enumerate()
        .map(|(index, digit)| {
            if index % 2 == 0 {
                *digit
            } else {
                let doubled = digit * 2;
                if doubled > 9 { doubled - 9 } else { doubled }
            }
        })
        .sum();
    sum % 10 == 0
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct DispatchKey {
    origin: String,
    detector_id: String,
    pattern: String,
    regex_mode: String,
    match_strategy: String,
    post_filter: String,
    output_token: String,
    replacement_scope: String,
}

impl DispatchKey {
    fn from_row(row: &Value) -> Self {
        Self {
            origin: text(row, "origin").to_owned(),
            detector_id: text(row, "detector_id").to_owned(),
            pattern: text(row, "pattern").to_owned(),
            regex_mode: text(row, "regex_mode").to_owned(),
            match_strategy: text(row, "match_strategy").to_owned(),
            post_filter: text(row, "post_filter").to_owned(),
            output_token: text(row, "output_token").to_owned(),
            replacement_scope: text(row, "replacement_scope").to_owned(),
        }
    }

    fn mutate(&mut self, field: &str, value: &str) {
        match field {
            "origin" => value.clone_into(&mut self.origin),
            "detector_id" => value.clone_into(&mut self.detector_id),
            "pattern" => value.clone_into(&mut self.pattern),
            "regex_mode" => value.clone_into(&mut self.regex_mode),
            "match_strategy" => value.clone_into(&mut self.match_strategy),
            "post_filter" => value.clone_into(&mut self.post_filter),
            "output_token" => value.clone_into(&mut self.output_token),
            "replacement_scope" => value.clone_into(&mut self.replacement_scope),
            _ => panic!("unsupported dispatch mutation field {field}"),
        }
    }
}

fn validate_post_capture_provenance_refresh(corpus: &Value) -> Result<(), String> {
    let refresh = &corpus["post_capture_provenance_refresh"];
    for (key, expected) in [
        ("refresh_id", PROVENANCE_REFRESH_ID),
        ("recorded_date_utc", "2026-08-06"),
        ("refresh_state", "STATIC_SOURCE_PIN_MAINTENANCE"),
        ("execution_state", "NOT_RUN_BY_R2_1_STATIC_LANE"),
        ("path", BASELINE_PATH),
    ] {
        if refresh.get(key).and_then(Value::as_str) != Some(expected) {
            return Err(format!("provenance refresh {key} must be {expected}"));
        }
    }

    let previous = &refresh["previous_pin"];
    if text(previous, "authority_revision") != BASELINE_AUTHORITY_REVISION
        || text(previous, "sha256") != BASELINE_PREVIOUS_SHA256
        || number(previous, "line_count") != 1_357
    {
        return Err("previous baseline pin receipt drifted".to_owned());
    }

    let current = &refresh["current_pin"];
    if text(current, "last_change_revision") != BASELINE_CURRENT_REVISION
        || text(current, "sha256") != BASELINE_CURRENT_SHA256
        || number(current, "line_count") != 3_210
    {
        return Err("current baseline pin receipt drifted".to_owned());
    }
    let baseline_pin = array(corpus, "source_pins")
        .iter()
        .find(|pin| pin.get("path").and_then(Value::as_str) == Some(BASELINE_PATH))
        .ok_or_else(|| "current baseline source pin is missing".to_owned())?;
    if text(baseline_pin, "sha256") != text(current, "sha256")
        || number(baseline_pin, "line_count") != number(current, "line_count")
    {
        return Err("refresh receipt and current baseline source pin disagree".to_owned());
    }

    let classification = &refresh["change_classification"];
    if text(classification, "classification") != "APPEND_ONLY_INDEPENDENT_PHASE2_STATIC_AUDITS"
        || number(classification, "inserted_lines") != 1_853
        || number(classification, "deleted_lines") != 0
    {
        return Err("baseline drift classification changed".to_owned());
    }
    let expected_objects: BTreeSet<String> = [
        "hash_map_static_audit",
        "host_benchmark_metadata_static_audit",
        "phase2_terminal_readiness_static_audit",
        "slab_static_audit",
        "visibility_macro_static_audit",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect();
    if array(classification, "added_top_level_objects").len() != expected_objects.len()
        || string_set(classification, "added_top_level_objects") != expected_objects
    {
        return Err("added baseline object set drifted".to_owned());
    }
    let expected_revisions: BTreeSet<String> = [
        "4d5748b3de2c15985af55e3dfe3c35626d6be543",
        "42a66e7f4e6733c28c59405c052c68f7a32ea0d7",
        "1472b388e365460c2dc067b57f084291e6d8d407",
        "33f94643ced8f5415ad3c1f0a30cd42ddcb738c9",
        BASELINE_CURRENT_REVISION,
    ]
    .into_iter()
    .map(str::to_owned)
    .collect();
    if array(classification, "change_revisions").len() != expected_revisions.len()
        || string_set(classification, "change_revisions") != expected_revisions
    {
        return Err("baseline change revision set drifted".to_owned());
    }

    let row_hashes = object(classification, "unchanged_capability_rows");
    if row_hashes.len() != 2
        || row_hashes.get(CAPABILITY_ID).and_then(Value::as_str)
            != Some(REGEX_CAPABILITY_ROW_SHA256)
        || row_hashes
            .get("CAP-LAB-DETERMINISM")
            .and_then(Value::as_str)
            != Some(LAB_CAPABILITY_ROW_SHA256)
    {
        return Err("unchanged capability-row receipt drifted".to_owned());
    }

    let preservation = object(refresh, "preservation");
    let expected_preservation_keys: BTreeSet<String> = [
        "detector_vectors_changed",
        "pipeline_vectors_changed",
        "dispatch_negative_fixtures_changed",
        "dispatch_allowset_changed",
        "corpus_policy_changed",
        "authority_decision_changed",
        "production_source_changed",
        "dependency_exit_allowed",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect();
    let actual_preservation_keys: BTreeSet<String> = preservation.keys().cloned().collect();
    if actual_preservation_keys != expected_preservation_keys
        || preservation
            .values()
            .any(|value| value.as_bool() != Some(false))
    {
        return Err("provenance refresh preservation boundary drifted".to_owned());
    }

    let no_claim = text(refresh, "no_claim_boundary");
    for required in [
        "does not execute the R2.1 contract",
        "change any corpus vector or dispatch rule",
        "authorize dependency exit or cutover",
        "close the tracker",
    ] {
        if !no_claim.contains(required) {
            return Err(format!("refresh no-claim boundary missing {required}"));
        }
    }
    Ok(())
}

fn validate_inventory(corpus: &Value) -> Result<(), String> {
    for (key, expected) in [
        ("artifact_id", ARTIFACT_ID),
        ("program_id", PROGRAM_ID),
        ("bead_id", BEAD_ID),
        ("capability_id", CAPABILITY_ID),
        ("source_revision", SOURCE_REVISION),
        ("authority_revision", AUTHORITY_REVISION),
        ("baseline_authority_revision", BASELINE_AUTHORITY_REVISION),
        ("r1_evidence_revision", R1_EVIDENCE_REVISION),
        ("supersedes_detector_corpus", R1_CORPUS_REFERENCE),
    ] {
        if corpus.get(key).and_then(Value::as_str) != Some(expected) {
            return Err(format!("{key} must be {expected}"));
        }
    }
    if corpus.get("schema_version").and_then(Value::as_u64) != Some(1) {
        return Err("schema_version must be 1".to_owned());
    }
    if contains_unknown(corpus) {
        return Err("corpus must contain no UNKNOWN text".to_owned());
    }
    validate_post_capture_provenance_refresh(corpus)?;

    let pin_scope = &corpus["source_pin_scope"];
    if number(pin_scope, "path_count") != 8
        || text(pin_scope, "paths_sha256") != SOURCE_PIN_PATHS_SHA256
    {
        return Err("source pin scope count or path projection drifted".to_owned());
    }

    let authority = object(corpus, "authority");
    if authority.get("current_action").and_then(Value::as_str) != Some("KEEP_INCUMBENT")
        || authority
            .get("dependency_exit_allowed")
            .and_then(Value::as_bool)
            != Some(false)
        || authority
            .get("custom_pattern_fast_path_allowed")
            .and_then(Value::as_bool)
            != Some(false)
    {
        return Err("authority must keep the incumbent and forbid custom dispatch".to_owned());
    }
    for (key, owner) in [
        ("email_and_ssn_owner", "asupersync-5z2scg.8.2.2"),
        ("card_and_luhn_owner", "asupersync-5z2scg.8.2.3"),
        ("phone_and_dispatch_owner", "asupersync-5z2scg.8.2.4"),
        ("terminal_receipt_owner", "asupersync-5z2scg.8.2.5"),
    ] {
        if authority.get(key).and_then(Value::as_str) != Some(owner) {
            return Err(format!("{key} must remain routed to {owner}"));
        }
    }

    let policy = object(corpus, "policy");
    if policy.get("zero_unknown_required").and_then(Value::as_bool) != Some(true)
        || policy.get("unknown_rows").and_then(Value::as_u64) != Some(0)
        || policy.get("execution_state").and_then(Value::as_str)
            != Some("NOT_RUN_BY_R2_1_STATIC_LANE")
        || policy
            .get("detector_vector_output_rule")
            .and_then(Value::as_str)
            != Some("AUTO_ENABLED_ACCEPT_USES_DETECTOR_TOKEN_ELSE_PRESERVE_INPUT")
        || policy
            .get("unrecognized_or_conflicting_dispatch")
            .and_then(Value::as_str)
            != Some("FALL_THROUGH_TO_INCUMBENT_WITHOUT_PARTIAL_RESULT")
    {
        return Err("static execution and fallback policy drifted".to_owned());
    }

    let detectors = array(corpus, "detectors");
    let expected_detectors: BTreeSet<String> = [
        "RGX-BUILTIN-EMAIL",
        "RGX-BUILTIN-SSN",
        "RGX-BUILTIN-CARD",
        "RGX-BUILTIN-PHONE",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect();
    if detectors.len() != 4 || row_ids(detectors, "detector_id") != expected_detectors {
        return Err("four-detector identity set drifted".to_owned());
    }
    for (detector_id, owner) in [
        ("RGX-BUILTIN-EMAIL", "asupersync-5z2scg.8.2.2"),
        ("RGX-BUILTIN-SSN", "asupersync-5z2scg.8.2.2"),
        ("RGX-BUILTIN-CARD", "asupersync-5z2scg.8.2.3"),
        ("RGX-BUILTIN-PHONE", "asupersync-5z2scg.8.2.4"),
    ] {
        let detector = find_row(detectors, "detector_id", detector_id);
        if detector.get("implementation_owner").and_then(Value::as_str) != Some(owner) {
            return Err(format!("{detector_id} must remain routed to {owner}"));
        }
    }
    let order: Vec<u64> = detectors.iter().map(|row| number(row, "order")).collect();
    if order != [1, 2, 3, 4] {
        return Err("detector order must remain email, SSN, card, phone".to_owned());
    }

    let capabilities = array(corpus, "capabilities");
    if capabilities.len() != 8 || row_ids(capabilities, "capability_id").len() != 8 {
        return Err("capability identities must contain eight unique rows".to_owned());
    }
    if capabilities
        .iter()
        .any(|row| row.get("parent_capability_id").and_then(Value::as_str) != Some(CAPABILITY_ID))
    {
        return Err("every corpus capability must remain under CAP-REGEX-PRIVACY".to_owned());
    }
    let provenance = array(corpus, "provenance");
    if provenance.len() != 4 || row_ids(provenance, "provenance_id").len() != 4 {
        return Err("provenance must contain four unique rows".to_owned());
    }

    let detector_vectors = array(corpus, "detector_vectors");
    let pipeline_vectors = array(corpus, "pipeline_vectors");
    let negative_fixtures = array(corpus, "dispatch_negative_fixtures");
    if detector_vectors.len() != 62 || pipeline_vectors.len() != 19 || negative_fixtures.len() != 8
    {
        return Err("corpus vector counts drifted".to_owned());
    }
    let all_case_ids: BTreeSet<String> = detector_vectors
        .iter()
        .chain(pipeline_vectors)
        .map(|row| text(row, "case_id").to_owned())
        .collect();
    if all_case_ids.len() != detector_vectors.len() + pipeline_vectors.len() {
        return Err("case IDs must be globally unique".to_owned());
    }
    let crosswalk = array(corpus, "r1_case_crosswalk");
    if crosswalk.len() != 11 || row_ids(crosswalk, "r1_case_id").len() != 11 {
        return Err("R1 crosswalk must contain eleven unique source IDs".to_owned());
    }
    let exact_crosswalk_rows = crosswalk
        .iter()
        .filter(|row| text(row, "relationship") == "EXACT_INPUT_AND_OUTCOME")
        .count();
    if exact_crosswalk_rows != 3 {
        return Err("R1 crosswalk must retain three exact-input rows".to_owned());
    }
    for row in crosswalk {
        if !all_case_ids.contains(text(row, "r2_case_id")) {
            return Err(format!(
                "{} maps to an unknown R2 case",
                text(row, "r1_case_id")
            ));
        }
        if !matches!(
            text(row, "relationship"),
            "EXACT_INPUT_AND_OUTCOME" | "SEMANTIC_EQUIVALENT_OUTCOME_CLASS"
        ) {
            return Err(format!(
                "{} has an unsupported crosswalk relationship",
                text(row, "r1_case_id")
            ));
        }
    }
    if row_ids(negative_fixtures, "fixture_id").len() != negative_fixtures.len() {
        return Err("dispatch fixture IDs must be unique".to_owned());
    }

    let provenance_ids = row_ids(provenance, "provenance_id");
    let capability_ids = row_ids(capabilities, "capability_id");
    for detector in detectors {
        for key in ["span_capability_id", "post_filter_capability_id"] {
            match detector.get(key).and_then(Value::as_str) {
                Some(capability_id) if !capability_ids.contains(capability_id) => {
                    return Err(format!(
                        "{} has unknown {key} {capability_id}",
                        text(detector, "detector_id")
                    ));
                }
                Some(_) | None => {}
            }
        }
    }
    for row in detector_vectors.iter().chain(pipeline_vectors) {
        if !provenance_ids.contains(text(row, "provenance_id")) {
            return Err(format!("{} has unknown provenance", text(row, "case_id")));
        }
        for capability in array(row, "capability_ids") {
            let capability = capability
                .as_str()
                .ok_or_else(|| format!("{} capability must be text", text(row, "case_id")))?;
            if !capability_ids.contains(capability) {
                return Err(format!(
                    "{} has unknown capability {capability}",
                    text(row, "case_id")
                ));
            }
        }
    }

    let required_tags = string_set(corpus, "required_coverage_tags_per_detector");
    let mut vectors_by_detector: BTreeMap<String, usize> = BTreeMap::new();
    let mut tags_by_detector: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for row in detector_vectors {
        let detector_id = text(row, "detector_id").to_owned();
        if !expected_detectors.contains(&detector_id) {
            return Err(format!("{} has unknown detector", text(row, "case_id")));
        }
        *vectors_by_detector.entry(detector_id.clone()).or_default() += 1;
        tags_by_detector
            .entry(detector_id)
            .or_default()
            .extend(string_set(row, "coverage_tags"));
    }
    for detector_id in &expected_detectors {
        if tags_by_detector.get(detector_id) != Some(&required_tags) {
            return Err(format!("{detector_id} required coverage tags drifted"));
        }
    }
    let expected_counts: BTreeMap<String, usize> = [
        ("RGX-BUILTIN-EMAIL".to_owned(), 15),
        ("RGX-BUILTIN-SSN".to_owned(), 12),
        ("RGX-BUILTIN-CARD".to_owned(), 17),
        ("RGX-BUILTIN-PHONE".to_owned(), 18),
    ]
    .into_iter()
    .collect();
    if vectors_by_detector != expected_counts {
        return Err("per-detector vector counts drifted".to_owned());
    }
    for (detector_id, expected_count) in &expected_counts {
        let declared_count = usize::try_from(number(
            &corpus["coverage_matrix"]["detector_counts"],
            detector_id,
        ))
        .map_err(|_| format!("{detector_id} declared count does not fit usize"))?;
        if declared_count != *expected_count {
            return Err(format!("{detector_id} coverage summary count drifted"));
        }
    }

    let coverage = object(corpus, "coverage_matrix");
    if coverage
        .get("detector_vector_count")
        .and_then(Value::as_u64)
        != Some(62)
        || coverage
            .get("pipeline_vector_count")
            .and_then(Value::as_u64)
            != Some(19)
        || coverage
            .get("dispatch_negative_fixture_count")
            .and_then(Value::as_u64)
            != Some(8)
        || coverage
            .get("synthetic_values_only")
            .and_then(Value::as_bool)
            != Some(true)
        || coverage.get("unknown_rows").and_then(Value::as_u64) != Some(0)
    {
        return Err("coverage summary drifted".to_owned());
    }

    let allowset = object(corpus, "dispatch_allowset");
    let expected_identity_fields: BTreeSet<String> = [
        "origin",
        "detector_id",
        "pattern",
        "regex_mode",
        "match_strategy",
        "post_filter",
        "output_token",
        "replacement_scope",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect();
    if allowset
        .get("custom_pattern_text_equality_is_builtin_identity")
        .and_then(Value::as_bool)
        != Some(false)
        || allowset.get("state").and_then(Value::as_str)
            != Some("SPECIFICATION_ONLY_NOT_IMPLEMENTED")
        || allowset
            .get("duplicate_or_conflicting_identity_action")
            .and_then(Value::as_str)
            != Some("FALL_THROUGH_TO_INCUMBENT_WITHOUT_PARTIAL_RESULT")
        || allowset
            .get("unrecognized_identity_action")
            .and_then(Value::as_str)
            != Some("FALL_THROUGH_TO_INCUMBENT_WITHOUT_PARTIAL_RESULT")
        || string_set(&corpus["dispatch_allowset"], "identity_fields") != expected_identity_fields
        || row_ids(negative_fixtures, "mutation_field") != expected_identity_fields
    {
        return Err("dispatch allowset identity or fallback policy drifted".to_owned());
    }

    let no_claims = array(corpus, "no_claim_boundaries");
    let joined = no_claims
        .iter()
        .map(|row| row.as_str().ok_or("no-claim rows must be text"))
        .collect::<Result<Vec<_>, _>>()?
        .join("\n");
    for required in [
        "implements no scanner or fast path",
        "does not authorize changing or removing regex",
        "does not claim exhaustive detection",
        "UTF-8 byte offsets",
        "does not prove latency",
        "does not authorize tracker closure",
    ] {
        if !joined.contains(required) {
            return Err(format!("missing no-claim boundary {required}"));
        }
    }
    Ok(())
}

#[test]
fn schema_references_coverage_and_claim_projection_are_closed() {
    let corpus = artifact();
    validate_inventory(&corpus).expect("R2.1 corpus must be structurally valid");
    assert_eq!(
        canonical_sha256(&claims_projection(&corpus)),
        CLAIMS_PROJECTION_SHA256,
        "canonical semantic claims projection drifted"
    );
}

#[test]
fn source_pins_and_authority_rows_are_current() {
    let corpus = artifact();
    let pins = array(&corpus, "source_pins");
    assert_eq!(
        pins.len(),
        usize::try_from(number(&corpus["source_pin_scope"], "path_count"))
            .expect("source pin count fits usize"),
    );

    let mut paths = BTreeSet::new();
    for pin in pins {
        let path = text(pin, "path");
        assert!(paths.insert(path.to_owned()), "duplicate source pin {path}");
        let bytes = read_repo_bytes(path);
        assert_eq!(
            sha256_hex(&bytes),
            text(pin, "sha256"),
            "{path} hash drifted"
        );
        let source = String::from_utf8(bytes).expect("pinned source must be UTF-8");
        assert_eq!(
            source.lines().count(),
            usize::try_from(number(pin, "line_count")).expect("line count fits usize"),
            "{path} line count drifted",
        );
    }
    let mut path_projection = String::new();
    for path in &paths {
        path_projection.push_str(path);
        path_projection.push('\n');
    }
    assert_eq!(
        sha256_hex(path_projection.as_bytes()),
        SOURCE_PIN_PATHS_SHA256
    );

    let registry = parse_repo_json(REGISTRY_PATH);
    let registry_rows = array(&registry, "capabilities");
    let registry_row = find_row(registry_rows, "capability_id", CAPABILITY_ID);
    assert_eq!(text(registry_row, "disposition"), "KEEP_UNTIL_PARITY");
    assert_eq!(text(registry_row, "cutover_state"), "KEEP_INCUMBENT");

    let baseline = parse_repo_json(BASELINE_PATH);
    let baseline_rows = array(&baseline, "capability_baselines");
    let baseline_row = find_row(baseline_rows, "capability_id", CAPABILITY_ID);
    assert_eq!(
        text(baseline_row, "baseline_state"),
        "EXECUTABLE_PARTIAL_BLOCKING"
    );
    assert_eq!(baseline_row["cutover_eligible"].as_bool(), Some(false));
    for (capability_id, expected_sha256) in [
        (CAPABILITY_ID, REGEX_CAPABILITY_ROW_SHA256),
        ("CAP-LAB-DETERMINISM", LAB_CAPABILITY_ROW_SHA256),
    ] {
        let row = find_row(baseline_rows, "capability_id", capability_id);
        assert_eq!(
            canonical_sha256(row),
            expected_sha256,
            "{capability_id} canonical baseline row drifted",
        );
    }

    let r1 = parse_repo_json(R1_ARTIFACT_PATH);
    assert_eq!(text(&r1, "capability_id"), CAPABILITY_ID);
    let r1_rows = array(&r1, "built_in_detector_corpus");
    assert_eq!(r1_rows.len(), 11);
    let crosswalk = array(&corpus, "r1_case_crosswalk");
    assert_eq!(
        row_ids(crosswalk, "r1_case_id"),
        row_ids(r1_rows, "case_id"),
        "R1 crosswalk must preserve every historical case ID",
    );

    let detector_vectors = array(&corpus, "detector_vectors");
    let pipeline_vectors = array(&corpus, "pipeline_vectors");
    let detectors = array(&corpus, "detectors");
    for link in crosswalk {
        let r1_row = find_row(r1_rows, "case_id", text(link, "r1_case_id"));
        let r2_row = detector_vectors
            .iter()
            .chain(pipeline_vectors)
            .find(|row| {
                row.get("case_id").and_then(Value::as_str) == Some(text(link, "r2_case_id"))
            })
            .expect("crosswalk target must exist");
        let r2_input = materialize_input(r2_row);
        let r2_output = if let Some(detector_id) = r2_row.get("detector_id").and_then(Value::as_str)
        {
            let detector = find_row(detectors, "detector_id", detector_id);
            if flag(r2_row, "expected_detector_accepts") {
                text(detector, "output_token").to_owned()
            } else {
                r2_input.clone()
            }
        } else {
            text(r2_row, "expected_output").to_owned()
        };

        if text(link, "relationship") == "EXACT_INPUT_AND_OUTCOME" {
            assert_eq!(r2_input, text(r1_row, "value"));
        }
        if text(r1_row, "output") == text(r1_row, "value") {
            assert_eq!(
                r2_output,
                r2_input,
                "{} preserve outcome",
                text(link, "r1_case_id"),
            );
        } else {
            assert_eq!(
                r2_output,
                text(r1_row, "output"),
                "{} token outcome",
                text(link, "r1_case_id"),
            );
        }
    }
}

#[test]
fn live_pattern_identity_order_tokens_and_custom_priority_are_pinned() {
    let corpus = artifact();
    let source = read_repo_file(SOURCE_PATH);
    let detectors = array(&corpus, "detectors");

    for detector in detectors {
        let pattern = text(detector, "pattern");
        assert!(
            source.contains(&format!("r\"{pattern}\"")),
            "{} exact raw pattern missing from live source",
            text(detector, "detector_id")
        );
        assert!(
            source.contains(text(detector, "output_token")),
            "{} output token missing from live source",
            text(detector, "detector_id")
        );
        assert_eq!(text(detector, "origin"), "BUILTIN");
        assert_eq!(text(detector, "replacement_scope"), "WHOLE_INPUT_VALUE");
    }

    let positions = [
        source
            .find("let email_re =")
            .expect("email detector source"),
        source.find("let ssn_re =").expect("SSN detector source"),
        source
            .find("let card_candidate_re =")
            .expect("card detector source"),
        source
            .find("let phone_re =")
            .expect("phone detector source"),
    ];
    assert!(positions.windows(2).all(|pair| pair[0] < pair[1]));
    assert!(source.contains(".find_iter(value)"));
    assert!(source.contains(".any(Self::is_luhn_valid_card)"));

    let custom = source
        .find("if self.matches_custom_pii_pattern(value)")
        .expect("custom pattern priority source");
    let automatic = source
        .find("if self.auto_pii_detection")
        .expect("automatic detector source");
    assert!(custom < automatic, "custom patterns must remain first");
}

#[test]
fn independent_detector_vectors_match_incumbent_spans_and_luhn() {
    let corpus = artifact();
    let detectors = array(&corpus, "detectors");

    for row in array(&corpus, "detector_vectors") {
        let input = materialize_input(row);
        let detector_id = text(row, "detector_id");
        let detector = find_row(detectors, "detector_id", detector_id);
        let regex = Regex::new(text(detector, "pattern"))
            .unwrap_or_else(|error| panic!("{detector_id} pattern must compile: {error}"));

        let actual: Vec<(usize, usize, Option<bool>)> = regex
            .find_iter(&input)
            .map(|matched| {
                let luhn =
                    (detector_id == "RGX-BUILTIN-CARD").then(|| independent_luhn(matched.as_str()));
                (matched.start(), matched.end(), luhn)
            })
            .collect();
        let expected: Vec<(usize, usize, Option<bool>)> = array(row, "expected_matches")
            .iter()
            .map(|span| {
                let start = usize::try_from(number(span, "start_byte")).expect("start fits usize");
                let end = usize::try_from(number(span, "end_byte")).expect("end fits usize");
                assert!(start <= end && end <= input.len());
                assert!(input.is_char_boundary(start) && input.is_char_boundary(end));
                let luhn = span.get("luhn_valid").and_then(Value::as_bool);
                if detector_id == "RGX-BUILTIN-CARD" {
                    assert!(luhn.is_some(), "card span must declare Luhn validity");
                } else {
                    assert!(
                        luhn.is_none(),
                        "non-card span must not declare Luhn validity"
                    );
                }
                (start, end, luhn)
            })
            .collect();
        assert_eq!(actual, expected, "{} span drift", text(row, "case_id"));

        let accepts = if detector_id == "RGX-BUILTIN-CARD" {
            actual.iter().any(|(_, _, luhn)| *luhn == Some(true))
        } else {
            !actual.is_empty()
        };
        assert_eq!(
            accepts,
            flag(row, "expected_detector_accepts"),
            "{} acceptance drift",
            text(row, "case_id")
        );

        let expected_output = if accepts {
            text(detector, "output_token")
        } else {
            &input
        };
        assert_eq!(
            PrivacyConfig::new()
                .with_auto_pii_detection()
                .redact_pii("synthetic.corpus", &input),
            expected_output,
            "{} whole-value output drift",
            text(row, "case_id")
        );
    }
}

fn detector_accepts(detector: &Value, input: &str) -> bool {
    let regex = Regex::new(text(detector, "pattern")).expect("frozen pattern must compile");
    if text(detector, "detector_id") == "RGX-BUILTIN-CARD" {
        regex
            .find_iter(input)
            .any(|matched| independent_luhn(matched.as_str()))
    } else {
        regex.is_match(input)
    }
}

#[test]
fn public_pipeline_preserves_order_whole_value_tokens_and_custom_origin() {
    let corpus = artifact();
    let detectors = array(&corpus, "detectors");

    for row in array(&corpus, "pipeline_vectors") {
        let input = materialize_input(row);
        let mut config = PrivacyConfig::new();
        if flag(row, "auto_pii_detection") {
            config = config.with_auto_pii_detection();
        }
        if let Some(pattern) = row.get("custom_pattern").and_then(Value::as_str) {
            config = config
                .try_with_pii_pattern(pattern)
                .expect("pipeline custom pattern must compile");
        }
        assert_eq!(
            config.redact_pii("synthetic.corpus", &input),
            text(row, "expected_output"),
            "{} public output drift",
            text(row, "case_id")
        );

        let mut visited = Vec::new();
        let mut selected = if let Some(pattern) = row.get("custom_pattern").and_then(Value::as_str)
        {
            visited.push("CUSTOM".to_owned());
            Regex::new(pattern)
                .expect("valid custom pattern")
                .is_match(&input)
                .then(|| "CUSTOM".to_owned())
        } else {
            None
        };
        if selected.is_none() && flag(row, "auto_pii_detection") {
            for detector in detectors {
                let detector_id = text(detector, "detector_id").to_owned();
                visited.push(detector_id.clone());
                if detector_accepts(detector, &input) {
                    selected = Some(detector_id);
                    break;
                }
            }
        }

        let expected_visited: Vec<String> = array(row, "expected_visited_detectors")
            .iter()
            .map(|entry| entry.as_str().expect("visited detector text").to_owned())
            .collect();
        assert_eq!(
            visited,
            expected_visited,
            "{} visit order",
            text(row, "case_id")
        );
        assert_eq!(
            selected.as_deref(),
            row.get("expected_selected_detector")
                .and_then(Value::as_str),
            "{} selected detector",
            text(row, "case_id")
        );
    }

    for (case_id, detector_id) in [
        ("RGX-R2-PIPE-012", "RGX-BUILTIN-EMAIL"),
        ("RGX-R2-PIPE-015", "RGX-BUILTIN-SSN"),
        ("RGX-R2-PIPE-016", "RGX-BUILTIN-CARD"),
        ("RGX-R2-PIPE-017", "RGX-BUILTIN-PHONE"),
    ] {
        let collision = find_row(array(&corpus, "pipeline_vectors"), "case_id", case_id);
        let detector = find_row(detectors, "detector_id", detector_id);
        assert_eq!(text(collision, "custom_pattern"), text(detector, "pattern"));
        assert_eq!(text(collision, "expected_selected_detector"), "CUSTOM");
        assert_eq!(text(collision, "expected_output"), "[REDACTED]");
    }

    let nonmatch = find_row(
        array(&corpus, "pipeline_vectors"),
        "case_id",
        "RGX-R2-PIPE-018",
    );
    assert_eq!(
        text(nonmatch, "expected_selected_detector"),
        "RGX-BUILTIN-EMAIL"
    );
    let automatic_disabled = find_row(
        array(&corpus, "pipeline_vectors"),
        "case_id",
        "RGX-R2-PIPE-019",
    );
    assert!(!flag(automatic_disabled, "auto_pii_detection"));
    assert_eq!(
        text(automatic_disabled, "expected_selected_detector"),
        "CUSTOM"
    );
}

#[test]
fn dispatch_allowset_is_exact_and_negative_fixtures_fall_through() {
    let corpus = artifact();
    let detectors = array(&corpus, "detectors");
    let allowed: BTreeSet<DispatchKey> = detectors.iter().map(DispatchKey::from_row).collect();
    assert_eq!(allowed.len(), 4);

    let allowset = &corpus["dispatch_allowset"];
    assert_eq!(
        string_set(allowset, "allowed_detector_ids"),
        row_ids(detectors, "detector_id")
    );
    assert_eq!(
        string_set(allowset, "identity_fields"),
        [
            "origin",
            "detector_id",
            "pattern",
            "regex_mode",
            "match_strategy",
            "post_filter",
            "output_token",
            "replacement_scope",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect()
    );

    for fixture in array(&corpus, "dispatch_negative_fixtures") {
        let base = find_row(detectors, "detector_id", text(fixture, "base_detector_id"));
        let mut candidate = DispatchKey::from_row(base);
        candidate.mutate(
            text(fixture, "mutation_field"),
            text(fixture, "candidate_value"),
        );
        assert!(
            !allowed.contains(&candidate),
            "{} accidentally entered the exact allowset",
            text(fixture, "fixture_id")
        );
        assert_eq!(
            text(fixture, "expected_action"),
            "FALL_THROUGH_TO_INCUMBENT_WITHOUT_PARTIAL_RESULT"
        );
    }
}

#[test]
fn docs_ignore_rule_and_static_no_claims_are_discoverable() {
    let doc = read_repo_file(DOC_PATH);
    assert_eq!(doc.matches(DOC_BEGIN).count(), 1);
    assert_eq!(doc.matches(DOC_END).count(), 1);
    for required in [
        "KEEP_UNTIL_PARITY",
        "UTF-8 byte ranges",
        "pattern text alone is insufficient",
        PROVENANCE_REFRESH_ID,
        "STATIC_SOURCE_PIN_MAINTENANCE",
        "1,853 lines and lost none",
        "NOT_RUN_BY_R2_1_STATIC_LANE",
        "implements no scanner",
        "No local Cargo fallback is approved",
    ] {
        assert!(doc.contains(required), "documentation missing {required}");
    }

    let ignore = read_repo_file(IGNORE_PATH);
    assert!(
        ignore
            .lines()
            .any(|line| line == "!artifacts/regex_built_in_detector_corpus_v1.json")
    );
}

#[test]
fn structural_mutations_fail_closed() {
    let original = artifact();

    let mut unknown = original.clone();
    unknown["policy"]["unknown_rows"] = Value::from(1);
    assert!(validate_inventory(&unknown).is_err());

    let mut duplicate = original.clone();
    let first = duplicate["detector_vectors"][0].clone();
    duplicate["detector_vectors"]
        .as_array_mut()
        .expect("detector vectors")
        .push(first);
    assert!(validate_inventory(&duplicate).is_err());

    let mut missing_tag = original.clone();
    let tags = missing_tag["detector_vectors"][0]["coverage_tags"]
        .as_array_mut()
        .expect("coverage tags");
    tags.retain(|tag| tag.as_str() != Some("empty"));
    assert!(validate_inventory(&missing_tag).is_err());

    let mut custom_dispatch = original.clone();
    custom_dispatch["authority"]["custom_pattern_fast_path_allowed"] = Value::Bool(true);
    assert!(validate_inventory(&custom_dispatch).is_err());

    let mut overclaim = original;
    overclaim["dispatch_allowset"]["state"] = Value::String("IMPLEMENTED".to_owned());
    assert!(validate_inventory(&overclaim).is_err());

    let mut semantic_refresh = artifact();
    semantic_refresh["post_capture_provenance_refresh"]["preservation"]["detector_vectors_changed"] =
        Value::Bool(true);
    assert!(validate_inventory(&semantic_refresh).is_err());
}
