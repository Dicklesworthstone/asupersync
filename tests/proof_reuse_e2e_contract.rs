#![allow(missing_docs)]

use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

const AGENTS_PATH: &str = "AGENTS.md";
const CACHE_CONTRACT_PATH: &str = "artifacts/proof_reuse_cache_contract_v1.json";
const CONTRACT_PATH: &str = "artifacts/proof_reuse_e2e_contract_v1.json";
const CONTRACT_TEST_PATH: &str = "tests/proof_reuse_e2e_contract.rs";
const FRESHNESS_HELPER_PATH: &str = "scripts/proof_artifact_freshness_receipt.py";
const HANDOFF_CONTRACT_PATH: &str = "artifacts/proof_reuse_handoff_receipt_contract_v1.json";
const MANIFEST_PATH: &str = "artifacts/proof_lane_manifest_v1.json";
const REUSE_QUERY_JSON_GOLDEN_PATH: &str =
    "tests/fixtures/proof_artifact_freshness_receipt/reuse_index_query_expected.json";
const REUSE_QUERY_MARKDOWN_GOLDEN_PATH: &str =
    "tests/fixtures/proof_artifact_freshness_receipt/reuse_index_query_expected.md";
const SNAPSHOT_PATH: &str = "artifacts/proof_status_snapshot_v1.json";

struct ValidationContext {
    cache_reason_codes: BTreeSet<String>,
    e2e_reason_codes: BTreeSet<String>,
    handoff_example_ids: BTreeSet<String>,
    lanes: BTreeMap<String, Value>,
    proof_statuses: BTreeSet<String>,
    redaction_classes: BTreeSet<String>,
}

fn repo_path(relative: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(relative)
}

fn read_repo_file(relative: &str) -> String {
    std::fs::read_to_string(repo_path(relative))
        .unwrap_or_else(|err| panic!("read {relative}: {err}"))
}

fn json_file(relative: &str) -> Value {
    serde_json::from_str(&read_repo_file(relative))
        .unwrap_or_else(|err| panic!("parse {relative}: {err}"))
}

fn contract() -> Value {
    json_file(CONTRACT_PATH)
}

fn array<'a>(value: &'a Value, key: &str) -> &'a Vec<Value> {
    value
        .get(key)
        .and_then(Value::as_array)
        .unwrap_or_else(|| panic!("{key} must be an array"))
}

fn object<'a>(value: &'a Value, key: &str) -> &'a Value {
    value
        .get(key)
        .unwrap_or_else(|| panic!("{key} must be present"))
}

fn string<'a>(value: &'a Value, key: &str) -> &'a str {
    let text = value
        .get(key)
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("{key} must be a string"));
    assert!(!text.trim().is_empty(), "{key} must be nonempty");
    text
}

fn optional_string<'a>(value: &'a Value, key: &str) -> Option<&'a str> {
    match value.get(key) {
        Some(Value::Null) | None => None,
        Some(Value::String(text)) => {
            if text.is_empty() {
                None
            } else {
                Some(text)
            }
        }
        _ => panic!("{key} must be a string or null"),
    }
}

fn bool_field(value: &Value, key: &str) -> bool {
    value
        .get(key)
        .and_then(Value::as_bool)
        .unwrap_or_else(|| panic!("{key} must be a boolean"))
}

fn u64_field(value: &Value, key: &str) -> u64 {
    value
        .get(key)
        .and_then(Value::as_u64)
        .unwrap_or_else(|| panic!("{key} must be an unsigned integer"))
}

fn i64_field(value: &Value, key: &str) -> i64 {
    value
        .get(key)
        .and_then(Value::as_i64)
        .unwrap_or_else(|| panic!("{key} must be an integer"))
}

fn string_set(value: &Value, key: &str) -> BTreeSet<String> {
    array(value, key)
        .iter()
        .map(|item| {
            let text = item
                .as_str()
                .unwrap_or_else(|| panic!("{key} entries must be strings"));
            assert!(!text.trim().is_empty(), "{key} entries must be nonempty");
            text.to_string()
        })
        .collect()
}

fn string_vec(value: &Value, key: &str) -> Vec<String> {
    array(value, key)
        .iter()
        .map(|item| {
            item.as_str()
                .unwrap_or_else(|| panic!("{key} entries must be strings"))
                .to_string()
        })
        .collect()
}

fn manifest_lanes() -> BTreeMap<String, Value> {
    array(&json_file(MANIFEST_PATH), "lanes")
        .iter()
        .map(|lane| (string(lane, "lane_id").to_string(), lane.clone()))
        .collect()
}

fn proof_evidence_statuses() -> BTreeSet<String> {
    array(&json_file(SNAPSHOT_PATH), "proof_evidence_status_catalog")
        .iter()
        .map(|status| string(status, "status").to_string())
        .collect()
}

fn handoff_example_ids() -> BTreeSet<String> {
    array(&json_file(HANDOFF_CONTRACT_PATH), "handoff_examples")
        .iter()
        .map(|example| string(example, "example_id").to_string())
        .collect()
}

fn handoff_redaction_classes() -> BTreeSet<String> {
    string_set(
        object(&json_file(HANDOFF_CONTRACT_PATH), "policy"),
        "allowed_redaction_classes",
    )
}

fn cache_reason_codes() -> BTreeSet<String> {
    string_set(&json_file(CACHE_CONTRACT_PATH), "refusal_reason_codes")
}

fn context(contract: &Value) -> ValidationContext {
    ValidationContext {
        cache_reason_codes: cache_reason_codes(),
        e2e_reason_codes: string_set(object(contract, "policy"), "allowed_e2e_reason_codes"),
        handoff_example_ids: handoff_example_ids(),
        lanes: manifest_lanes(),
        proof_statuses: proof_evidence_statuses(),
        redaction_classes: handoff_redaction_classes(),
    }
}

fn ensure_no_disallowed_fields(value: &Value, disallowed: &BTreeSet<String>) -> Result<(), String> {
    match value {
        Value::Object(map) => {
            for (key, child) in map {
                if disallowed.contains(key) {
                    return Err(format!("disallowed field {key} present"));
                }
                ensure_no_disallowed_fields(child, disallowed)?;
            }
        }
        Value::Array(items) => {
            for item in items {
                ensure_no_disallowed_fields(item, disallowed)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn ensure_no_secret_like_strings(value: &Value, markers: &BTreeSet<String>) -> Result<(), String> {
    match value {
        Value::String(text) => {
            let lower = text.to_ascii_lowercase();
            for marker in markers {
                if lower.contains(marker) {
                    return Err(format!("secret-like marker {marker} present"));
                }
            }
        }
        Value::Object(map) => {
            for child in map.values() {
                ensure_no_secret_like_strings(child, markers)?;
            }
        }
        Value::Array(items) => {
            for item in items {
                ensure_no_secret_like_strings(item, markers)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn reason_codes(scenario: &Value) -> Vec<String> {
    string_vec(object(scenario, "handoff"), "refusal_reason_codes")
}

fn classifier_reason_codes(scenario: &Value) -> Vec<String> {
    string_vec(object(scenario, "classifier"), "reason_codes")
}

fn stage_names(scenario: &Value) -> Vec<String> {
    array(scenario, "stage_log")
        .iter()
        .map(|stage| string(stage, "stage").to_string())
        .collect()
}

fn validate_stage_order(scenario: &Value, required: &[String]) -> Result<(), String> {
    let scenario_id = string(scenario, "scenario_id");
    let stages = stage_names(scenario);
    if stages != required {
        return Err(format!("{scenario_id}: stage order drifted"));
    }
    for stage in array(scenario, "stage_log") {
        string(stage, "stage");
        string(stage, "status");
        string(stage, "detail");
    }
    Ok(())
}

fn validate_known_reason_codes(
    scenario_id: &str,
    reasons: &[String],
    ctx: &ValidationContext,
) -> Result<(), String> {
    for reason in reasons {
        if !ctx.cache_reason_codes.contains(reason) && !ctx.e2e_reason_codes.contains(reason) {
            return Err(format!("{scenario_id}: unknown reason code {reason}"));
        }
    }
    Ok(())
}

fn validate_manifest_policy(
    scenario: &Value,
    ctx: &ValidationContext,
) -> Result<(String, Value), String> {
    let scenario_id = string(scenario, "scenario_id");
    let request = object(scenario, "request");
    let manifest_policy = object(scenario, "manifest_policy");
    let handoff = object(scenario, "handoff");
    let lane_id = string(request, "manifest_lane_id");
    if string(manifest_policy, "lane_id") != lane_id {
        return Err(format!("{scenario_id}: manifest policy lane mismatch"));
    }
    let lane = ctx
        .lanes
        .get(lane_id)
        .ok_or_else(|| format!("{scenario_id}: unknown manifest lane {lane_id}"))?;
    let lane_policy = object(lane, "proof_reuse_policy");
    let allowed_scopes = string_set(lane_policy, "allowed_claim_scopes");
    let claim_scope = string(request, "claim_scope");
    if bool_field(manifest_policy, "claim_scope_allowed") != allowed_scopes.contains(claim_scope) {
        return Err(format!(
            "{scenario_id}: manifest claim scope allowance drifted"
        ));
    }
    if bool_field(manifest_policy, "cache_reuse_allowed")
        != bool_field(lane_policy, "cache_hits_allowed")
    {
        return Err(format!("{scenario_id}: cache reuse policy drifted"));
    }
    if bool_field(manifest_policy, "requires_fresh_rerun_when_dirty_overlap")
        != bool_field(lane_policy, "requires_fresh_rerun_when_dirty_overlap")
    {
        return Err(format!("{scenario_id}: dirty-overlap policy drifted"));
    }
    let lane_command = string(lane, "command");
    if string(manifest_policy, "rerun_command") != lane_command {
        return Err(format!(
            "{scenario_id}: manifest rerun command must match lane command"
        ));
    }
    if string(handoff, "rerun_command") != lane_command {
        return Err(format!(
            "{scenario_id}: handoff rerun command must match lane command"
        ));
    }
    Ok((lane_id.to_string(), lane_policy.clone()))
}

fn validate_scenario(
    scenario: &Value,
    contract: &Value,
    ctx: &ValidationContext,
) -> Result<(), String> {
    let scenario_id = string(scenario, "scenario_id");
    ensure_no_disallowed_fields(scenario, &string_set(contract, "disallowed_fields"))?;
    ensure_no_secret_like_strings(scenario, &string_set(contract, "secret_like_markers"))?;
    validate_stage_order(
        scenario,
        &string_vec(object(contract, "policy"), "required_stage_sequence"),
    )?;

    let request = object(scenario, "request");
    let classifier = object(scenario, "classifier");
    let handoff = object(scenario, "handoff");
    let final_verdict = object(scenario, "final_verdict");
    let provenance = object(scenario, "rch_remote_provenance");
    let dirty_frontier = object(scenario, "dirty_frontier");
    let coverage = object(scenario, "touched_surface_coverage");
    let reasons = reason_codes(scenario);
    let classifier_reasons = classifier_reason_codes(scenario);
    let (lane_id, lane_policy) = validate_manifest_policy(scenario, ctx)?;

    if !bool_field(provenance, "remote_required") {
        return Err(format!("{scenario_id}: remote_required must be true"));
    }
    if !string(handoff, "rerun_command").starts_with(string(
        object(contract, "policy"),
        "required_rerun_command_prefix",
    )) {
        return Err(format!("{scenario_id}: rerun command must use remote RCH"));
    }
    if bool_field(handoff, "cache_hit_is_fresh_rch_pass") {
        return Err(format!(
            "{scenario_id}: cache hit cannot be marked fresh RCH pass"
        ));
    }
    if bool_field(handoff, "raw_log_excerpt_included")
        || bool_field(handoff, "raw_agent_mail_body_included")
    {
        return Err(format!("{scenario_id}: raw payloads must be suppressed"));
    }
    if array(coverage, "covered_paths").is_empty() {
        return Err(format!("{scenario_id}: coverage must name covered paths"));
    }
    if !ctx
        .redaction_classes
        .contains(string(handoff, "redaction_class"))
    {
        return Err(format!("{scenario_id}: unknown redaction class"));
    }
    if !ctx
        .proof_statuses
        .contains(string(final_verdict, "proof_evidence_status"))
    {
        return Err(format!("{scenario_id}: unknown proof evidence status"));
    }
    if string(final_verdict, "proof_evidence_status") != string(handoff, "proof_evidence_status") {
        return Err(format!("{scenario_id}: handoff proof status mismatch"));
    }
    if string(final_verdict, "verdict") != string(handoff, "decision")
        && string(final_verdict, "verdict") != "no-win"
    {
        return Err(format!("{scenario_id}: final verdict/handoff mismatch"));
    }
    if !string_set(object(contract, "policy"), "allowed_final_verdicts")
        .contains(string(final_verdict, "verdict"))
    {
        return Err(format!("{scenario_id}: unknown final verdict"));
    }
    for reason in &classifier_reasons {
        if !reasons.contains(reason) {
            return Err(format!(
                "{scenario_id}: classifier reason {reason} missing from handoff"
            ));
        }
    }
    validate_known_reason_codes(scenario_id, &reasons, ctx)?;

    if let Some(handoff_fixture_id) = optional_string(handoff, "handoff_fixture_id") {
        if !ctx.handoff_example_ids.contains(handoff_fixture_id) {
            return Err(format!(
                "{scenario_id}: unknown handoff fixture {handoff_fixture_id}"
            ));
        }
    }

    match string(final_verdict, "verdict") {
        "approved-cache-hit" => {
            if string(classifier, "decision") != "reusable" {
                return Err(format!(
                    "{scenario_id}: approved cache hit needs reusable classifier decision"
                ));
            }
            if !bool_field(classifier, "safe_to_reuse")
                || !bool_field(final_verdict, "safe_to_reuse")
                || !bool_field(final_verdict, "safe_to_cite")
            {
                return Err(format!("{scenario_id}: approved cache hit must be safe"));
            }
            if !reasons.is_empty() {
                return Err(format!(
                    "{scenario_id}: approved cache hit must not carry refusal reasons"
                ));
            }
            if optional_string(handoff, "chosen_proof_id").is_none() {
                return Err(format!("{scenario_id}: approved cache hit needs proof id"));
            }
            if !bool_field(provenance, "local_fallback_absent") {
                return Err(format!(
                    "{scenario_id}: approved cache hit requires absent local fallback"
                ));
            }
            if string(dirty_frontier, "verdict") != "clean" {
                return Err(format!(
                    "{scenario_id}: approved cache hit requires clean frontier"
                ));
            }
            if !string(handoff, "operator_statement")
                .to_ascii_lowercase()
                .contains("not a fresh rch rerun")
            {
                return Err(format!(
                    "{scenario_id}: approved cache hit must state it is not fresh"
                ));
            }
        }
        "rerun-required" | "refused" | "no-win" => {
            if bool_field(classifier, "safe_to_reuse")
                || bool_field(final_verdict, "safe_to_reuse")
                || bool_field(final_verdict, "safe_to_cite")
            {
                return Err(format!("{scenario_id}: non-hit verdict must be unsafe"));
            }
            if reasons.is_empty() {
                return Err(format!("{scenario_id}: non-hit verdict needs reasons"));
            }
            if optional_string(handoff, "chosen_proof_id").is_some() {
                return Err(format!(
                    "{scenario_id}: non-hit verdict must not choose proof"
                ));
            }
        }
        other => return Err(format!("{scenario_id}: unsupported final verdict {other}")),
    }

    if reasons
        .iter()
        .any(|reason| reason == "dirty-frontier-overlap")
    {
        if string(dirty_frontier, "verdict") != "dirty-overlap" {
            return Err(format!(
                "{scenario_id}: dirty-overlap reason needs dirty-overlap verdict"
            ));
        }
        if array(dirty_frontier, "overlap_paths").is_empty()
            || array(coverage, "uncovered_paths").is_empty()
        {
            return Err(format!(
                "{scenario_id}: dirty-overlap reason needs overlap and uncovered paths"
            ));
        }
        if !bool_field(&lane_policy, "requires_fresh_rerun_when_dirty_overlap") {
            return Err(format!(
                "{scenario_id}: dirty-overlap lane must require fresh rerun"
            ));
        }
    }
    if reasons
        .iter()
        .any(|reason| reason == "local-fallback-marker")
    {
        if bool_field(provenance, "local_fallback_absent") {
            return Err(format!(
                "{scenario_id}: local fallback reason must record fallback presence"
            ));
        }
        if string(handoff, "redaction_class") != "refused" {
            return Err(format!(
                "{scenario_id}: local fallback must use refused redaction"
            ));
        }
    }
    if reasons.iter().any(|reason| reason == "failed-proof-status") {
        let blocker = optional_string(handoff, "first_blocker_line").unwrap_or("");
        if blocker.is_empty() {
            return Err(format!(
                "{scenario_id}: failed proof status needs first blocker line"
            ));
        }
        if let Some(outcome) = scenario.get("candidate_outcome") {
            if i64_field(outcome, "exit_code") == 0 {
                return Err(format!("{scenario_id}: failed proof must be nonzero"));
            }
        }
    }
    if reasons
        .iter()
        .any(|reason| reason == "stale-head" || reason == "branch-mismatch")
        && string(final_verdict, "proof_evidence_status") != "stale-evidence"
        && string(final_verdict, "verdict") != "no-win"
    {
        return Err(format!(
            "{scenario_id}: stale/branch mismatch must be stale evidence"
        ));
    }
    if reasons
        .iter()
        .any(|reason| reason == "broad-claim-unsupported")
    {
        if bool_field(object(scenario, "manifest_policy"), "claim_scope_allowed") {
            return Err(format!(
                "{scenario_id}: broad unsupported claim was unexpectedly allowed"
            ));
        }
        if string(final_verdict, "proof_evidence_status") != "unsupported" {
            return Err(format!(
                "{scenario_id}: broad unsupported claim must use unsupported status"
            ));
        }
    }
    if reasons.iter().any(|reason| reason == "toolchain-mismatch")
        && scenario.get("fingerprint_mismatch").is_none()
    {
        return Err(format!(
            "{scenario_id}: toolchain mismatch must name mismatched fingerprints"
        ));
    }
    if reasons
        .iter()
        .any(|reason| reason == "rch-unavailable-no-safe-cache")
    {
        let admission = object(scenario, "rch_admission");
        if bool_field(admission, "available") {
            return Err(format!(
                "{scenario_id}: no-win admission must be unavailable"
            ));
        }
        if string(final_verdict, "proof_evidence_status") != "no-win" {
            return Err(format!("{scenario_id}: RCH unavailable must be no-win"));
        }
        if optional_string(handoff, "first_blocker_line").is_none() {
            return Err(format!("{scenario_id}: no-win needs first blocker line"));
        }
    }
    if reasons
        .iter()
        .any(|reason| reason == "secret-like-data-redacted")
    {
        let redaction = object(scenario, "redaction");
        if !bool_field(redaction, "raw_coordination_payload_suppressed")
            || !bool_field(redaction, "raw_log_payload_suppressed")
            || !bool_field(redaction, "secret_like_payload_suppressed")
        {
            return Err(format!(
                "{scenario_id}: redaction scenario must suppress unsafe payloads"
            ));
        }
        if string(handoff, "redaction_class") != "redacted"
            || string(handoff, "log_excerpt_policy") != "first-blocker-line-only"
        {
            return Err(format!(
                "{scenario_id}: redaction scenario must retain only first blocker"
            ));
        }
    }

    if lane_id == "clippy-all-targets" && string(request, "claim_scope") != "clippy-frontier" {
        return Err(format!("{scenario_id}: clippy lane claim drifted"));
    }

    Ok(())
}

fn generated_summary(contract: &Value) -> Value {
    let mut verdict_counts = BTreeMap::<String, u64>::new();
    let mut scenario_verdicts = Vec::new();
    let mut fresh_count = 0;
    let mut raw_count = 0;

    for scenario in array(contract, "scenarios") {
        let handoff = object(scenario, "handoff");
        let final_verdict = object(scenario, "final_verdict");
        let verdict = string(final_verdict, "verdict").to_string();
        *verdict_counts.entry(verdict.clone()).or_default() += 1;
        if bool_field(handoff, "cache_hit_is_fresh_rch_pass") {
            fresh_count += 1;
        }
        if bool_field(handoff, "raw_log_excerpt_included")
            || bool_field(handoff, "raw_agent_mail_body_included")
        {
            raw_count += 1;
        }
        scenario_verdicts.push(json!({
            "scenario_id": string(scenario, "scenario_id"),
            "proof_evidence_status": string(final_verdict, "proof_evidence_status"),
            "verdict": verdict,
            "reason_codes": reason_codes(scenario),
        }));
    }

    json!({
        "contract_version": string(contract, "contract_version"),
        "scenario_count": array(contract, "scenarios").len(),
        "verdict_counts": verdict_counts,
        "cache_hit_is_fresh_rch_pass_count": fresh_count,
        "raw_payload_included_count": raw_count,
        "stage_sequence": string_vec(object(contract, "policy"), "required_stage_sequence"),
        "scenario_verdicts": scenario_verdicts,
    })
}

fn generated_markdown_summary(contract: &Value) -> String {
    let summary = generated_summary(contract);
    let counts = object(&summary, "verdict_counts");
    let mut text = String::new();
    text.push_str("# Proof reuse E2E contract v1\n\n");
    text.push_str(&format!(
        "- scenarios: {}\n",
        u64_field(&summary, "scenario_count")
    ));
    text.push_str(&format!(
        "- approved-cache-hit: {}\n",
        counts["approved-cache-hit"].as_u64().unwrap_or(0)
    ));
    text.push_str(&format!(
        "- rerun-required: {}\n",
        counts["rerun-required"].as_u64().unwrap_or(0)
    ));
    text.push_str(&format!(
        "- refused: {}\n",
        counts["refused"].as_u64().unwrap_or(0)
    ));
    text.push_str(&format!(
        "- no-win: {}\n",
        counts["no-win"].as_u64().unwrap_or(0)
    ));
    text.push_str(&format!(
        "- cache_hit_is_fresh_rch_pass: {}\n",
        u64_field(&summary, "cache_hit_is_fresh_rch_pass_count")
    ));
    text.push_str(&format!(
        "- raw_payloads_included: {}\n\n",
        u64_field(&summary, "raw_payload_included_count")
    ));
    text.push_str("## Scenario verdicts\n");
    for (index, scenario) in array(contract, "scenarios").iter().enumerate() {
        let final_verdict = object(scenario, "final_verdict");
        let reasons = reason_codes(scenario);
        let reason_text = if reasons.is_empty() {
            "<none>".to_string()
        } else {
            reasons.join(",")
        };
        text.push_str(&format!(
            "{}. {} | verdict={} | proof={} | reasons={}\n",
            index + 1,
            string(scenario, "scenario_id"),
            string(final_verdict, "verdict"),
            string(final_verdict, "proof_evidence_status"),
            reason_text
        ));
    }
    text
}

fn scenario_by_id<'a>(contract: &'a Value, scenario_id: &str) -> &'a Value {
    array(contract, "scenarios")
        .iter()
        .find(|scenario| scenario["scenario_id"].as_str() == Some(scenario_id))
        .unwrap_or_else(|| panic!("scenario {scenario_id} must exist"))
}

#[test]
fn e2e_contract_declares_sources_and_no_network_policy() {
    let contract = contract();
    assert_eq!(
        contract.get("contract_version").and_then(Value::as_str),
        Some("proof-reuse-e2e-contract-v1")
    );
    assert_eq!(
        contract.get("bead_id").and_then(Value::as_str),
        Some("asupersync-5pziae.6")
    );

    let source = contract.get("source_of_truth").expect("source_of_truth");
    assert_eq!(source["contract"].as_str(), Some(CONTRACT_PATH));
    assert_eq!(source["contract_test"].as_str(), Some(CONTRACT_TEST_PATH));
    assert_eq!(
        source["proof_reuse_cache_contract"].as_str(),
        Some(CACHE_CONTRACT_PATH)
    );
    assert_eq!(
        source["proof_reuse_handoff_contract"].as_str(),
        Some(HANDOFF_CONTRACT_PATH)
    );
    assert_eq!(source["proof_lane_manifest"].as_str(), Some(MANIFEST_PATH));
    assert_eq!(
        source["proof_status_snapshot"].as_str(),
        Some(SNAPSHOT_PATH)
    );
    assert_eq!(
        source["proof_freshness_helper"].as_str(),
        Some(FRESHNESS_HELPER_PATH)
    );
    assert_eq!(
        source["reuse_query_json_golden"].as_str(),
        Some(REUSE_QUERY_JSON_GOLDEN_PATH)
    );
    assert_eq!(
        source["reuse_query_markdown_golden"].as_str(),
        Some(REUSE_QUERY_MARKDOWN_GOLDEN_PATH)
    );
    assert_eq!(source["agent_instructions"].as_str(), Some(AGENTS_PATH));

    for path in [
        CONTRACT_PATH,
        CONTRACT_TEST_PATH,
        CACHE_CONTRACT_PATH,
        HANDOFF_CONTRACT_PATH,
        MANIFEST_PATH,
        SNAPSHOT_PATH,
        FRESHNESS_HELPER_PATH,
        REUSE_QUERY_JSON_GOLDEN_PATH,
        REUSE_QUERY_MARKDOWN_GOLDEN_PATH,
        AGENTS_PATH,
    ] {
        assert!(repo_path(path).exists(), "source path must exist: {path}");
    }

    let policy = object(&contract, "policy");
    assert!(!bool_field(policy, "network_access_required"));
    assert!(!bool_field(policy, "tracker_mutation_allowed"));
    assert!(!bool_field(policy, "raw_agent_mail_bodies_allowed"));
    assert!(!bool_field(policy, "raw_log_excerpts_allowed"));
    assert!(bool_field(policy, "cache_hit_is_never_fresh_rch_pass"));
}

#[test]
fn e2e_scenarios_cover_required_paths_and_stage_order() {
    let contract = contract();
    let policy = object(&contract, "policy");
    let required_ids = string_set(policy, "required_scenario_ids");
    let actual_ids = array(&contract, "scenarios")
        .iter()
        .map(|scenario| string(scenario, "scenario_id").to_string())
        .collect::<BTreeSet<_>>();

    assert_eq!(actual_ids, required_ids);
    for scenario in array(&contract, "scenarios") {
        validate_stage_order(scenario, &string_vec(policy, "required_stage_sequence"))
            .unwrap_or_else(|error| panic!("{error}"));
    }
}

#[test]
fn e2e_scenarios_compose_cache_manifest_status_and_handoff_policies() {
    let contract = contract();
    let ctx = context(&contract);
    for scenario in array(&contract, "scenarios") {
        validate_scenario(scenario, &contract, &ctx).unwrap_or_else(|error| panic!("{error}"));
    }
}

#[test]
fn e2e_contract_tracks_existing_reuse_query_goldens() {
    let contract = contract();
    let reference = object(&contract, "reference_reuse_query");
    let query = json_file(string(reference, "json_golden"));
    assert_eq!(
        query["index_summary"]["candidate_count"].as_u64(),
        Some(u64_field(reference, "expected_candidate_count"))
    );
    assert_eq!(
        query["logs"][1]["accepted_count"].as_u64(),
        Some(u64_field(reference, "expected_accepted_count"))
    );
    assert_eq!(
        query["logs"][1]["refused_count"].as_u64(),
        Some(u64_field(reference, "expected_refused_count"))
    );
    assert_eq!(
        query["logs"][1]["miss_count"].as_u64(),
        Some(u64_field(reference, "expected_miss_count"))
    );
    assert_eq!(
        query["best_candidate"]["proof_id"].as_str(),
        Some(string(reference, "expected_best_candidate"))
    );
    let top_rerun_command = query["logs"]
        .as_array()
        .expect("reuse query logs")
        .iter()
        .find_map(|log| log["top_rerun_command"].as_str());
    assert_eq!(
        top_rerun_command,
        Some(string(reference, "expected_top_rerun_command"))
    );

    let markdown = read_repo_file(string(reference, "markdown_golden"));
    assert!(markdown.contains(string(reference, "expected_best_candidate")));
    assert!(markdown.contains(string(reference, "expected_top_rerun_command")));
}

#[test]
fn e2e_json_and_markdown_summaries_are_golden() {
    let contract = contract();
    assert_eq!(
        generated_summary(&contract),
        object(&contract, "expected_json_summary").clone()
    );
    assert_eq!(
        generated_markdown_summary(&contract),
        string(&contract, "expected_markdown_summary")
    );
}

#[test]
fn synthetic_bad_e2e_scenarios_are_rejected() {
    let contract = contract();
    let ctx = context(&contract);

    let mut fresh_claim = scenario_by_id(&contract, "exact-focused-cache-hit").clone();
    fresh_claim["handoff"]["cache_hit_is_fresh_rch_pass"] = Value::Bool(true);
    let error = validate_scenario(&fresh_claim, &contract, &ctx).unwrap_err();
    assert!(
        error.contains("fresh RCH pass"),
        "unexpected fresh-claim error: {error}"
    );

    let mut missing_stage = scenario_by_id(&contract, "exact-focused-cache-hit").clone();
    missing_stage["stage_log"][3]["stage"] = Value::String("manifest-policy".to_string());
    let error = validate_scenario(&missing_stage, &contract, &ctx).unwrap_err();
    assert!(
        error.contains("stage order"),
        "unexpected stage-order error: {error}"
    );

    let mut dirty_without_verdict =
        scenario_by_id(&contract, "frontier-dirty-overlap-rerun").clone();
    dirty_without_verdict["dirty_frontier"]["verdict"] = Value::String("clean".to_string());
    let error = validate_scenario(&dirty_without_verdict, &contract, &ctx).unwrap_err();
    assert!(
        error.contains("dirty-overlap verdict"),
        "unexpected dirty-verdict error: {error}"
    );

    let mut no_win_without_blocker = scenario_by_id(&contract, "rch-unavailable-no-win").clone();
    no_win_without_blocker["handoff"]["first_blocker_line"] = Value::String(String::new());
    let error = validate_scenario(&no_win_without_blocker, &contract, &ctx).unwrap_err();
    assert!(
        error.contains("first_blocker_line") || error.contains("first blocker"),
        "unexpected no-win blocker error: {error}"
    );

    let mut raw_payload = scenario_by_id(&contract, "redaction-first-blocker-only").clone();
    raw_payload["handoff"]["raw_log_excerpt_included"] = Value::Bool(true);
    let error = validate_scenario(&raw_payload, &contract, &ctx).unwrap_err();
    assert!(
        error.contains("raw payloads"),
        "unexpected raw-payload error: {error}"
    );

    let mut secret_payload = scenario_by_id(&contract, "redaction-first-blocker-only").clone();
    secret_payload["handoff"]["operator_statement"] =
        Value::String("token=must-not-appear".to_string());
    let error = validate_scenario(&secret_payload, &contract, &ctx).unwrap_err();
    assert!(
        error.contains("token="),
        "unexpected secret-payload error: {error}"
    );
}
