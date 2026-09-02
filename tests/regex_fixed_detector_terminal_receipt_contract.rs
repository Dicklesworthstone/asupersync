//! Terminal contract and named-host measurement emitter for regex R2.5.
//!
//! Bead: asupersync-5z2scg.8.2.5

#![cfg(feature = "metrics")]
#![allow(missing_docs)]

use asupersync::observability::otel::PrivacyConfig;
use regex::Regex;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fs;
use std::hint::black_box;
use std::path::PathBuf;
use std::time::Instant;

const ARTIFACT_PATH: &str = "artifacts/regex_fixed_detector_terminal_receipt_v1.json";
const CORPUS_PATH: &str = "artifacts/regex_built_in_detector_corpus_v1.json";
const DOC_PATH: &str = "docs/regex_fixed_detector_terminal_receipt.md";
const CLAIMS_PROJECTION_SHA256: &str =
    "1949fa0388595aeaea8cb271bda4ab75298f93d90755fae4ac0f4c1cd105660c";
const DOC_BEGIN: &str = "<!-- BEGIN REGEX FIXED DETECTOR TERMINAL RECEIPT -->";
const DOC_END: &str = "<!-- END REGEX FIXED DETECTOR TERMINAL RECEIPT -->";

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn read(path: &str) -> String {
    fs::read_to_string(repo_root().join(path))
        .unwrap_or_else(|error| panic!("read {path}: {error}"))
}

fn parse(path: &str) -> Value {
    serde_json::from_str(&read(path)).unwrap_or_else(|error| panic!("parse {path}: {error}"))
}

fn artifact() -> Value {
    parse(ARTIFACT_PATH)
}

fn object<'value>(value: &'value Value, key: &str) -> &'value serde_json::Map<String, Value> {
    value
        .get(key)
        .and_then(Value::as_object)
        .unwrap_or_else(|| panic!("{key} must be an object"))
}

fn array<'value>(value: &'value Value, key: &str) -> &'value [Value] {
    value
        .get(key)
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or_else(|| panic!("{key} must be an array"))
}

fn text<'value>(value: &'value Value, key: &str) -> &'value str {
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

fn boolean(value: &Value, key: &str) -> bool {
    value
        .get(key)
        .and_then(Value::as_bool)
        .unwrap_or_else(|| panic!("{key} must be boolean"))
}

fn sha256_bytes(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn sha256(path: &str) -> String {
    sha256_bytes(
        &fs::read(repo_root().join(path)).unwrap_or_else(|error| panic!("read {path}: {error}")),
    )
}

fn contains_unknown(value: &Value) -> bool {
    match value {
        Value::String(value) => value == "UNKNOWN",
        Value::Array(values) => values.iter().any(contains_unknown),
        Value::Object(values) => values.values().any(contains_unknown),
        Value::Null | Value::Bool(_) | Value::Number(_) => false,
    }
}

fn string_set(value: &Value, key: &str) -> BTreeSet<String> {
    array(value, key)
        .iter()
        .map(|entry| {
            entry
                .as_str()
                .unwrap_or_else(|| panic!("{key} entries must be text"))
                .to_owned()
        })
        .collect()
}

fn claims_projection(receipt: &Value) -> Value {
    json!({
        "authority": receipt["authority"].clone(),
        "source_pins": receipt["source_pins"].clone(),
        "predecessor_evidence": receipt["predecessor_evidence"].clone(),
        "detector_dispositions": receipt["detector_dispositions"].clone(),
        "pipeline_disposition": receipt["pipeline_disposition"].clone(),
        "dispatch_safety": receipt["dispatch_safety"].clone(),
        "bounded_resource_evidence": receipt["bounded_resource_evidence"].clone(),
        "named_host_measurements": receipt["named_host_measurements"].clone(),
        "replay_metadata": receipt["replay_metadata"].clone(),
        "rollback_triggers": receipt["rollback_triggers"].clone(),
        "no_claim_boundaries": receipt["no_claim_boundaries"].clone(),
    })
}

fn canonical_json(value: &Value, output: &mut String) {
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
                canonical_json(child, output);
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
                canonical_json(values.get(key).expect("canonical key exists"), output);
            }
            output.push('}');
        }
    }
}

fn canonical_sha256(value: &Value) -> String {
    let mut encoded = String::new();
    canonical_json(value, &mut encoded);
    sha256_bytes(encoded.as_bytes())
}

fn validate_receipt(receipt: &Value, corpus: &Value) -> Result<(), String> {
    for (key, expected) in [
        ("artifact_id", "regex-fixed-detector-terminal-receipt-v1"),
        ("program_id", "asupersync-ir2uf0"),
        ("bead_id", "asupersync-5z2scg.8.2.5"),
        ("capability_id", "CAP-REGEX-PRIVACY"),
    ] {
        if receipt.get(key).and_then(Value::as_str) != Some(expected) {
            return Err(format!("{key} drifted"));
        }
    }
    if receipt.get("schema_version").and_then(Value::as_u64) != Some(1) || contains_unknown(receipt)
    {
        return Err("receipt schema must be v1 with no UNKNOWN cells".to_owned());
    }

    let authority = object(receipt, "authority");
    if authority.get("terminal_state").and_then(Value::as_str)
        != Some("KEEP_INCUMBENT_DISABLE_REGRESSED_FIXED_FAST_PATHS")
        || authority
            .get("dependency_exit_allowed")
            .and_then(Value::as_bool)
            != Some(false)
        || authority
            .get("custom_pattern_fast_path_allowed")
            .and_then(Value::as_bool)
            != Some(false)
        || authority
            .get("unresolved_high_findings")
            .and_then(Value::as_u64)
            != Some(0)
    {
        return Err("terminal authority overclaims or retains a high finding".to_owned());
    }
    if string_set(&receipt["authority"], "authorized_fixed_fast_paths") != BTreeSet::new()
        || string_set(&receipt["authority"], "disabled_fixed_fast_paths")
            != BTreeSet::from([
                "RGX-BUILTIN-EMAIL".to_owned(),
                "RGX-BUILTIN-SSN".to_owned(),
                "RGX-BUILTIN-CARD".to_owned(),
                "RGX-BUILTIN-PHONE".to_owned(),
            ])
        || authority.get("rollback_revision").and_then(Value::as_str)
            != Some("d35453f0bdff943915dcf642fa09a30affb8a917")
    {
        return Err("terminal authorization set or rollback revision drifted".to_owned());
    }

    let pins = array(receipt, "source_pins");
    if pins.len() != 4 {
        return Err("terminal receipt must retain exactly four source pins".to_owned());
    }
    for pin in pins {
        let path = text(pin, "path");
        if sha256(path) != text(pin, "sha256")
            || read(path).lines().count()
                != usize::try_from(number(pin, "line_count")).expect("line count fits usize")
        {
            return Err(format!("source pin drifted for {path}"));
        }
    }

    let corpus_vectors = array(corpus, "detector_vectors");
    let expected_detector_cases: BTreeSet<String> = corpus_vectors
        .iter()
        .map(|row| text(row, "case_id").to_owned())
        .collect();
    let dispositions = array(receipt, "detector_dispositions");
    if dispositions.len() != 4 {
        return Err("exactly four detector disposition rows are required".to_owned());
    }
    let mut bound_detector_cases = BTreeSet::new();
    for row in dispositions {
        if text(row, "disposition") != "KEEP"
            || text(row, "reason") != "NAMED_HOST_LATENCY_AND_ALLOCATION_REGRESSION"
            || text(row, "source_revision").is_empty()
            || array(row, "replay_job_ids").is_empty()
        {
            return Err("regressed detector must retain source-bound KEEP evidence".to_owned());
        }
        for case_id in string_set(row, "case_ids") {
            if !bound_detector_cases.insert(case_id) {
                return Err("detector case IDs must be bound exactly once".to_owned());
            }
        }
    }
    if bound_detector_cases != expected_detector_cases {
        return Err("detector disposition rows do not cover all frozen cases".to_owned());
    }

    let expected_pipeline_cases: BTreeSet<String> = array(corpus, "pipeline_vectors")
        .iter()
        .map(|row| text(row, "case_id").to_owned())
        .collect();
    let pipeline = &receipt["pipeline_disposition"];
    if text(pipeline, "disposition") != "SAME"
        || string_set(pipeline, "case_ids") != expected_pipeline_cases
    {
        return Err("pipeline disposition does not cover all frozen outcomes".to_owned());
    }

    let dispatch = object(receipt, "dispatch_safety");
    if dispatch
        .get("custom_patterns_use_incumbent")
        .and_then(Value::as_bool)
        != Some(true)
        || dispatch
            .get("scanner_refusal_uses_incumbent")
            .and_then(Value::as_bool)
            != Some(true)
        || dispatch
            .get("fixed_scanner_fast_path_enabled")
            .and_then(Value::as_bool)
            != Some(false)
        || dispatch
            .get("production_automatic_detection_uses_incumbent")
            .and_then(Value::as_bool)
            != Some(true)
        || dispatch.get("built_in_order").and_then(Value::as_array)
            != Some(&vec![
                Value::String("RGX-BUILTIN-EMAIL".to_owned()),
                Value::String("RGX-BUILTIN-SSN".to_owned()),
                Value::String("RGX-BUILTIN-CARD".to_owned()),
                Value::String("RGX-BUILTIN-PHONE".to_owned()),
            ])
    {
        return Err("dispatch safety contract drifted".to_owned());
    }

    let bounds = object(receipt, "bounded_resource_evidence");
    if bounds.get("max_input_bytes").and_then(Value::as_u64) != Some(1_048_576)
        || bounds.get("max_matches").and_then(Value::as_u64) != Some(65_536)
        || bounds.get("max_work_units").and_then(Value::as_u64) != Some(16_777_280)
        || bounds.get("refusal_action").and_then(Value::as_str)
            != Some("FALL_THROUGH_TO_INCUMBENT_WITHOUT_PARTIAL_RESULT")
    {
        return Err("bounded resource evidence drifted".to_owned());
    }

    let measurements = object(receipt, "named_host_measurements");
    let latency_targets = measurements
        .get("latency_targets")
        .and_then(Value::as_array)
        .ok_or("latency targets must be an array")?;
    if latency_targets.len() < 2 {
        return Err("at least two named latency targets are required".to_owned());
    }
    for target in latency_targets {
        if text(target, "rch_job_id").is_empty()
            || text(target, "outcome") != "ALL_CANDIDATE_LATENCY_CELLS_REGRESSED"
            || array(target, "scenario_rows").len() != 6
        {
            return Err("named latency target is incomplete".to_owned());
        }
        for scenario in array(target, "scenario_rows") {
            let operations = array(scenario, "operations");
            if operations.len() != 2 {
                return Err("each latency scenario needs candidate and incumbent rows".to_owned());
            }
            for operation in operations {
                if number(operation, "sample_count") != 2_001
                    || number(operation, "operations_per_second") == 0
                    || number(operation, "p50_ns") == 0
                    || number(operation, "p95_ns") == 0
                    || number(operation, "p999_ns") == 0
                {
                    return Err("latency distribution contains an empty cell".to_owned());
                }
            }
            let candidate = &operations[0];
            let incumbent = &operations[1];
            if text(candidate, "operation") != "candidate"
                || text(incumbent, "operation") != "incumbent"
                || number(candidate, "operations_per_second")
                    >= number(incumbent, "operations_per_second")
                || number(candidate, "p50_ns") <= number(incumbent, "p50_ns")
                || number(candidate, "p95_ns") <= number(incumbent, "p95_ns")
                || number(candidate, "p999_ns") <= number(incumbent, "p999_ns")
            {
                return Err("latency regression decision is not supported by every cell".to_owned());
            }
        }
    }
    let allocations = measurements
        .get("allocation_targets")
        .and_then(Value::as_array)
        .ok_or("allocation targets must be an array")?;
    if allocations.len() != 2
        || allocations
            .iter()
            .any(|row| number(row, "allocation_calls") == 0 || text(row, "rch_job_id").is_empty())
    {
        return Err("candidate and incumbent allocation cells are required".to_owned());
    }
    let candidate = &allocations[0];
    let incumbent = &allocations[1];
    if text(candidate, "operation") != "candidate"
        || text(incumbent, "operation") != "incumbent"
        || number(candidate, "allocation_calls") <= number(incumbent, "allocation_calls")
        || number(candidate, "temporary_allocations") <= number(incumbent, "temporary_allocations")
        || text(candidate, "outcome") != "REGRESSION_AGAINST_INCUMBENT"
    {
        return Err("allocation regression decision is not supported".to_owned());
    }

    let replay = object(receipt, "replay_metadata");
    if replay.get("rollback_revision").and_then(Value::as_str)
        != Some("d35453f0bdff943915dcf642fa09a30affb8a917")
        || replay
            .get("rollback_focused_job_id")
            .and_then(Value::as_str)
            != Some("j-29988810699833448")
        || replay
            .get("rollback_corpus_contract_job_id")
            .and_then(Value::as_str)
            != Some("j-29988810699833449")
    {
        return Err("rollback replay evidence drifted".to_owned());
    }

    if canonical_sha256(&claims_projection(receipt)) != CLAIMS_PROJECTION_SHA256 {
        return Err("terminal claims projection drifted".to_owned());
    }
    Ok(())
}

#[test]
fn terminal_receipt_is_closed_complete_and_source_bound() {
    let receipt = artifact();
    let corpus = parse(CORPUS_PATH);
    validate_receipt(&receipt, &corpus).expect("R2.5 receipt must validate");
}

#[test]
fn every_frozen_public_pipeline_outcome_replays() {
    let corpus = parse(CORPUS_PATH);
    for row in array(&corpus, "pipeline_vectors") {
        let mut config = PrivacyConfig::new();
        if let Some(pattern) = row.get("custom_pattern").and_then(Value::as_str) {
            config = config
                .try_with_pii_pattern(pattern)
                .expect("frozen custom pattern compiles");
        }
        if boolean(row, "auto_pii_detection") {
            config = config.with_auto_pii_detection();
        }
        assert_eq!(
            config.redact_pii("r2.5.synthetic", text(row, "input")),
            text(row, "expected_output"),
            "{} public output",
            text(row, "case_id")
        );
    }
}

#[test]
fn terminal_receipt_mutations_fail_closed() {
    let corpus = parse(CORPUS_PATH);
    let original = artifact();

    let mut custom_cutover = original.clone();
    custom_cutover["authority"]["custom_pattern_fast_path_allowed"] = Value::Bool(true);
    assert!(validate_receipt(&custom_cutover, &corpus).is_err());

    let mut enabled_fast_path = original.clone();
    enabled_fast_path["dispatch_safety"]["fixed_scanner_fast_path_enabled"] = Value::Bool(true);
    enabled_fast_path["authority"]["authorized_fixed_fast_paths"] = json!(["RGX-BUILTIN-EMAIL"]);
    assert!(validate_receipt(&enabled_fast_path, &corpus).is_err());

    let mut missing_case = original.clone();
    missing_case["detector_dispositions"][0]["case_ids"]
        .as_array_mut()
        .expect("case IDs")
        .pop();
    assert!(validate_receipt(&missing_case, &corpus).is_err());

    let mut unknown = original.clone();
    unknown["authority"]["terminal_state"] = Value::String("UNKNOWN".to_owned());
    assert!(validate_receipt(&unknown, &corpus).is_err());

    let mut zero_allocation = original;
    zero_allocation["named_host_measurements"]["allocation_targets"][0]["allocation_calls"] =
        Value::from(0);
    assert!(validate_receipt(&zero_allocation, &corpus).is_err());
}

#[test]
fn documentation_markers_replay_commands_and_no_claims_are_discoverable() {
    let doc = read(DOC_PATH);
    assert_eq!(doc.matches(DOC_BEGIN).count(), 1);
    assert_eq!(doc.matches(DOC_END).count(), 1);
    for required in [
        "KEEP_INCUMBENT_DISABLE_REGRESSED_FIXED_FAST_PATHS",
        "RCH_REQUIRE_REMOTE=1",
        "heaptrack",
        "No local Cargo fallback is approved",
        "does not authorize dependency removal",
    ] {
        assert!(doc.contains(required), "documentation missing {required}");
    }
}

// BEGIN R2.5 NAMED-HOST MEASUREMENT HARNESS
const R2_5_SAMPLE_COUNT: usize = 2_001;
const R2_5_WARMUP_COUNT: usize = 64;

struct MeasurementScenario {
    id: &'static str,
    input: String,
}

fn measurement_scenarios() -> Vec<MeasurementScenario> {
    vec![
        MeasurementScenario {
            id: "email_hit",
            input: "Contact Jane.Doe@example.com for access".to_owned(),
        },
        MeasurementScenario {
            id: "ssn_hit",
            input: "SSN 123-45-6789".to_owned(),
        },
        MeasurementScenario {
            id: "card_hit",
            input: "Visa 4111 1111 1111 1111".to_owned(),
        },
        MeasurementScenario {
            id: "phone_hit",
            input: "Call +1 (415) 555-2671".to_owned(),
        },
        MeasurementScenario {
            id: "mixed_priority",
            input: "Call 415-555-2671 or mail first@example.com".to_owned(),
        },
        MeasurementScenario {
            id: "large_miss",
            input: "ordinary-synthetic-value;".repeat(2_048),
        },
    ]
}

struct IncumbentPrivacy {
    email: Regex,
    ssn: Regex,
    card: Regex,
    phone: Regex,
}

impl IncumbentPrivacy {
    fn new() -> Self {
        Self {
            email: Regex::new(r"(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,63}\b")
                .expect("email regex"),
            ssn: Regex::new(r"\b\d{3}-\d{2}-\d{4}\b").expect("SSN regex"),
            card: Regex::new(r"\b(?:\d[ -]?){13,19}\b").expect("card regex"),
            phone: Regex::new(r"(?x)\b(?:\+?1[\s.-]?)?(?:\(?\d{3}\)?[\s.-]?)\d{3}[\s.-]?\d{4}\b")
                .expect("phone regex"),
        }
    }

    fn redact(&self, value: &str) -> String {
        if self.email.is_match(value) {
            return "[EMAIL_REDACTED]".to_owned();
        }
        if self.ssn.is_match(value) {
            return "[SSN_REDACTED]".to_owned();
        }
        if self
            .card
            .find_iter(value)
            .any(|matched| independent_luhn(matched.as_str()))
        {
            return "[CARD_REDACTED]".to_owned();
        }
        if self.phone.is_match(value) {
            return "[PHONE_REDACTED]".to_owned();
        }
        value.to_owned()
    }
}

fn independent_luhn(candidate: &str) -> bool {
    let digits: Vec<u32> = candidate
        .chars()
        .filter_map(|value| value.to_digit(10))
        .collect();
    if !(13..=19).contains(&digits.len()) {
        return false;
    }
    digits
        .iter()
        .rev()
        .enumerate()
        .map(|(index, digit)| {
            if index % 2 == 1 {
                let doubled = digit * 2;
                if doubled > 9 { doubled - 9 } else { doubled }
            } else {
                *digit
            }
        })
        .sum::<u32>()
        % 10
        == 0
}

fn measure_once<T>(operation: impl FnOnce() -> T) -> (u64, T) {
    let started = Instant::now();
    let result = black_box(operation());
    let elapsed = u64::try_from(started.elapsed().as_nanos())
        .expect("single operation nanoseconds fit in u64")
        .max(1);
    (elapsed, result)
}

fn nearest_rank(samples: &[u64], numerator: usize, denominator: usize) -> u64 {
    let mut ordered = samples.to_vec();
    ordered.sort_unstable();
    let rank = numerator
        .checked_mul(ordered.len())
        .and_then(|value| value.checked_add(denominator - 1))
        .expect("bounded percentile rank")
        / denominator;
    ordered[rank.saturating_sub(1)]
}

fn distribution(operation: &str, samples: Vec<u64>, bytes_per_operation: usize) -> Value {
    let total_ns = samples.iter().copied().map(u128::from).sum::<u128>().max(1);
    let sample_count = u128::try_from(samples.len()).expect("sample count fits u128");
    let operations_per_second = sample_count
        .saturating_mul(1_000_000_000)
        .checked_div(total_ns)
        .expect("nonzero duration");
    let bytes_per_second = sample_count
        .saturating_mul(u128::try_from(bytes_per_operation).expect("byte count fits u128"))
        .saturating_mul(1_000_000_000)
        .checked_div(total_ns)
        .expect("nonzero duration");
    json!({
        "operation": operation,
        "sample_count": samples.len(),
        "bytes_per_operation": bytes_per_operation,
        "operations_per_second": u64::try_from(operations_per_second).expect("ops/s fits u64"),
        "bytes_per_second": u64::try_from(bytes_per_second).expect("bytes/s fits u64"),
        "p50_ns": nearest_rank(&samples, 50, 100),
        "p95_ns": nearest_rank(&samples, 95, 100),
        "p999_ns": nearest_rank(&samples, 999, 1_000),
        "raw_ns": samples,
    })
}

fn linux_host_metadata() -> Value {
    let cpu_model = fs::read_to_string("/proc/cpuinfo").ok().and_then(|source| {
        source.lines().find_map(|line| {
            line.strip_prefix("model name\t: ")
                .or_else(|| line.strip_prefix("Hardware\t: "))
                .map(str::to_owned)
        })
    });
    let memory_kib = fs::read_to_string("/proc/meminfo").ok().and_then(|source| {
        source
            .lines()
            .find_map(|line| line.strip_prefix("MemTotal:").map(str::trim))
            .and_then(|value| value.split_whitespace().next())
            .and_then(|value| value.parse::<u64>().ok())
    });
    json!({
        "os": std::env::consts::OS,
        "arch": std::env::consts::ARCH,
        "logical_parallelism": std::thread::available_parallelism().map_or(0, usize::from),
        "cpu_model": cpu_model,
        "memory_kib": memory_kib,
    })
}

#[test]
fn r2_5_release_performance_emitter() {
    let Ok(target_id) = std::env::var("R2_5_FIXED_DETECTOR_PERF_TARGET") else {
        return;
    };
    assert!(
        !read("src/observability/otel.rs")
            .contains("const FIXED_PII_SCANNER_FAST_PATH_ENABLED: bool = false;"),
        "the candidate was rolled back; replay the historical harness with --base \
         03a6fa83274c65f383c04d9a541bb94b2d3ee54f"
    );
    let operation_filter = std::env::var("R2_5_FIXED_DETECTOR_PERF_OPERATION").ok();
    assert!(matches!(
        operation_filter.as_deref(),
        None | Some("candidate" | "incumbent")
    ));

    let candidate = PrivacyConfig::new().with_auto_pii_detection();
    let incumbent = IncumbentPrivacy::new();
    let mut scenario_rows = Vec::new();
    for scenario in measurement_scenarios() {
        let expected = incumbent.redact(&scenario.input);
        assert_eq!(
            candidate.redact_pii("r2.5.synthetic", &scenario.input),
            expected,
            "{} preflight",
            scenario.id
        );
        for _ in 0..R2_5_WARMUP_COUNT {
            if operation_filter.as_deref() != Some("incumbent") {
                assert_eq!(
                    black_box(&candidate).redact_pii("r2.5.synthetic", black_box(&scenario.input)),
                    expected
                );
            }
            if operation_filter.as_deref() != Some("candidate") {
                assert_eq!(
                    black_box(&incumbent).redact(black_box(&scenario.input)),
                    expected
                );
            }
        }

        let mut operations = Vec::new();
        if operation_filter.as_deref() != Some("incumbent") {
            let mut samples = Vec::with_capacity(R2_5_SAMPLE_COUNT);
            for _ in 0..R2_5_SAMPLE_COUNT {
                let (elapsed, output) = measure_once(|| {
                    black_box(&candidate).redact_pii("r2.5.synthetic", black_box(&scenario.input))
                });
                assert_eq!(output, expected);
                samples.push(elapsed);
            }
            operations.push(distribution("candidate", samples, scenario.input.len()));
        }
        if operation_filter.as_deref() != Some("candidate") {
            let mut samples = Vec::with_capacity(R2_5_SAMPLE_COUNT);
            for _ in 0..R2_5_SAMPLE_COUNT {
                let (elapsed, output) =
                    measure_once(|| black_box(&incumbent).redact(black_box(&scenario.input)));
                assert_eq!(output, expected);
                samples.push(elapsed);
            }
            operations.push(distribution("incumbent", samples, scenario.input.len()));
        }
        scenario_rows.push(json!({
            "scenario_id": scenario.id,
            "input_bytes": scenario.input.len(),
            "expected_output": expected,
            "operations": operations,
        }));
    }

    let receipt = json!({
        "target_id": target_id,
        "host": linux_host_metadata(),
        "profile": "cargo test --release with debuginfo disabled",
        "sample_count_per_operation": R2_5_SAMPLE_COUNT,
        "warmup_count_per_operation": R2_5_WARMUP_COUNT,
        "percentile_method": "nearest-rank",
        "incumbent_revision": "regex@1.13.1",
        "operation_filter": operation_filter,
        "scenario_rows": scenario_rows,
    });
    println!("R2_5_FIXED_DETECTOR_RELEASE_PERF_RECEIPT={receipt}");

    let mut summary = receipt;
    for scenario in summary["scenario_rows"]
        .as_array_mut()
        .expect("scenario rows are an array")
    {
        for operation in scenario["operations"]
            .as_array_mut()
            .expect("operations are an array")
        {
            operation
                .as_object_mut()
                .expect("operation is an object")
                .remove("raw_ns");
        }
    }
    println!("R2_5_FIXED_DETECTOR_RELEASE_PERF_SUMMARY={summary}");
}
// END R2.5 NAMED-HOST MEASUREMENT HARNESS
