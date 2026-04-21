#![allow(warnings)]
#![allow(clippy::all)]
//! Semantic Verification Log Schema Validation (SEM-12.7)
//!
//! Bead: `asupersync-3cddg.12.7`
//! Schema: `sem-verification-log-v1`
//!
//! Contract tests that validate the log schema defined in
//! `docs/semantic_verification_log_schema.md`. Every verification tool
//! must emit entries conforming to this schema.
//!
//! These tests serve as the machine-readable specification for the schema:
//! if a test passes, the schema contract holds for that case.

#[macro_use]
mod common;

use common::*;
use serde_json::{Value, json};

// ============================================================================
// Schema Constants
// ============================================================================

const SCHEMA_VERSION: &str = "sem-verification-log-v1";
const SUMMARY_SCHEMA_VERSION: &str = "sem-verification-summary-v1";

const VALID_EVIDENCE_CLASSES: &[&str] = &["UT", "PT", "OC", "E2E", "LOG", "DOC", "CI"];
const VALID_VERDICTS: &[&str] = &["pass", "fail", "skip", "error"];
const VALID_PHASES: &[&str] = &["setup", "execute", "check", "teardown"];
const VALID_DOMAINS: &[&str] = &[
    "cancel",
    "obligation",
    "region",
    "outcome",
    "ownership",
    "combinator",
    "capability",
    "determinism",
];

/// All 47 canonical rule IDs from the semantic contract schema.
const CANONICAL_RULE_IDS: &[&str] = &[
    "rule.cancel.request",
    "rule.cancel.acknowledge",
    "rule.cancel.drain",
    "rule.cancel.finalize",
    "inv.cancel.idempotence",
    "inv.cancel.propagates_down",
    "def.cancel.reason_kinds",
    "def.cancel.severity_ordering",
    "prog.cancel.drains",
    "rule.cancel.checkpoint_masked",
    "inv.cancel.mask_bounded",
    "inv.cancel.mask_monotone",
    "rule.obligation.reserve",
    "rule.obligation.commit",
    "rule.obligation.abort",
    "rule.obligation.leak",
    "inv.obligation.no_leak",
    "inv.obligation.linear",
    "inv.obligation.bounded",
    "inv.obligation.ledger_empty_on_close",
    "prog.obligation.resolves",
    "rule.region.close_begin",
    "rule.region.close_cancel_children",
    "rule.region.close_children_done",
    "rule.region.close_run_finalizer",
    "rule.region.close_complete",
    "inv.region.quiescence",
    "prog.region.close_terminates",
    "def.outcome.four_valued",
    "def.outcome.severity_lattice",
    "def.outcome.join_semantics",
    "def.cancel.reason_ordering",
    "inv.ownership.single_owner",
    "inv.ownership.task_owned",
    "def.ownership.region_tree",
    "rule.ownership.spawn",
    "comb.join",
    "comb.race",
    "comb.timeout",
    "inv.combinator.loser_drained",
    "law.race.never_abandon",
    "law.join.assoc",
    "law.race.comm",
    "inv.capability.no_ambient",
    "def.capability.cx_scope",
    "inv.determinism.replayable",
    "def.determinism.seed_equivalence",
];

/// Oracle name to rule ID mapping.
const ORACLE_RULE_MAP: &[(&str, &[u32])] = &[
    ("task_leak", &[33, 34]),
    ("obligation_leak", &[16, 17]),
    ("quiescence", &[27]),
    ("cancellation_protocol", &[1, 2, 3, 4, 6]),
    ("loser_drain", &[40]),
    ("region_tree", &[35]),
    ("deadline_monotone", &[11, 19]),
    ("determinism", &[46, 47]),
    ("ambient_authority", &[44, 45]),
    ("finalizer", &[25]),
];

/// Domain to rule number range mapping.
const DOMAIN_RULE_RANGES: &[(&str, u32, u32)] = &[
    ("cancel", 1, 12),
    ("obligation", 13, 21),
    ("region", 22, 28),
    ("outcome", 29, 32),
    ("ownership", 33, 36),
    ("combinator", 37, 43),
    ("capability", 44, 45),
    ("determinism", 46, 47),
];

// ============================================================================
// Helpers
// ============================================================================

fn make_valid_entry() -> Value {
    json!({
        "schema_version": SCHEMA_VERSION,
        "entry_id": "svl-svr-000000000000002a-0000000000000001-000001",
        "run_id": "svr-000000000000002a-0000000000000001",
        "seq": 1,
        "timestamp_ns": 1000,
        "phase": "check",
        "rule_id": "rule.cancel.request",
        "rule_number": 1,
        "domain": "cancel",
        "evidence_class": "UT",
        "scenario_id": "WF-RACE.1",
        "verdict": "pass",
        "seed": 42,
        "repro_command": "cargo test --test adversarial_witness_corpus wf_race_1"
    })
}

/// Validate a log entry against the schema contract.
/// Returns a list of violation descriptions (empty = valid).
fn validate_entry(entry: &Value) -> Vec<String> {
    let mut violations = Vec::new();

    // 1. schema_version
    match entry.get("schema_version").and_then(Value::as_str) {
        Some(v) if v == SCHEMA_VERSION => {}
        Some(v) => violations.push(format!(
            "schema_version must be {SCHEMA_VERSION:?}, got {v:?}"
        )),
        None => violations.push("missing required field: schema_version".to_string()),
    }

    // 2. entry_id format: svl-{run_id}-{seq}
    match entry.get("entry_id").and_then(Value::as_str) {
        Some(id) if id.starts_with("svl-") => {}
        Some(id) => violations.push(format!("entry_id must start with 'svl-', got {id:?}")),
        None => violations.push("missing required field: entry_id".to_string()),
    }

    // 3. run_id
    if entry.get("run_id").and_then(Value::as_str).is_none() {
        violations.push("missing required field: run_id".to_string());
    }

    // 4. seq
    if entry.get("seq").and_then(Value::as_u64).is_none() {
        violations.push("missing required field: seq (u64)".to_string());
    }

    // 5. timestamp_ns
    if entry.get("timestamp_ns").and_then(Value::as_u64).is_none() {
        violations.push("missing required field: timestamp_ns (u64)".to_string());
    }

    // 6. phase
    match entry.get("phase").and_then(Value::as_str) {
        Some(p) if VALID_PHASES.contains(&p) => {}
        Some(p) => violations.push(format!("phase must be one of {VALID_PHASES:?}, got {p:?}")),
        None => violations.push("missing required field: phase".to_string()),
    }

    // 7. rule_id
    match entry.get("rule_id").and_then(Value::as_str) {
        Some(id) if CANONICAL_RULE_IDS.contains(&id) => {}
        Some(id) => violations.push(format!("rule_id {id:?} is not a canonical rule ID")),
        None => violations.push("missing required field: rule_id".to_string()),
    }

    // 8. rule_number
    match entry.get("rule_number").and_then(Value::as_u64) {
        Some(n) if (1..=47).contains(&n) => {}
        Some(n) => violations.push(format!("rule_number must be 1-47, got {n}")),
        None => violations.push("missing required field: rule_number (u32)".to_string()),
    }

    // 9. domain
    match entry.get("domain").and_then(Value::as_str) {
        Some(d) if VALID_DOMAINS.contains(&d) => {}
        Some(d) => violations.push(format!(
            "domain must be one of {VALID_DOMAINS:?}, got {d:?}"
        )),
        None => violations.push("missing required field: domain".to_string()),
    }

    // 10. evidence_class
    match entry.get("evidence_class").and_then(Value::as_str) {
        Some(c) if VALID_EVIDENCE_CLASSES.contains(&c) => {}
        Some(c) => violations.push(format!(
            "evidence_class must be one of {VALID_EVIDENCE_CLASSES:?}, got {c:?}"
        )),
        None => violations.push("missing required field: evidence_class".to_string()),
    }

    // 11. scenario_id
    if entry.get("scenario_id").and_then(Value::as_str).is_none() {
        violations.push("missing required field: scenario_id".to_string());
    }

    // 12. verdict
    let verdict = entry.get("verdict").and_then(Value::as_str);
    match verdict {
        Some(v) if VALID_VERDICTS.contains(&v) => {}
        Some(v) => violations.push(format!(
            "verdict must be one of {VALID_VERDICTS:?}, got {v:?}"
        )),
        None => violations.push("missing required field: verdict".to_string()),
    }

    // 13. verdict_reason required when fail/error
    if matches!(verdict, Some("fail" | "error")) {
        if entry
            .get("verdict_reason")
            .and_then(Value::as_str)
            .is_none()
        {
            violations.push("verdict_reason required when verdict is fail or error".to_string());
        }
    }

    // 14. seed + repro_command required when not skip
    if !matches!(verdict, Some("skip")) {
        if entry.get("seed").and_then(Value::as_u64).is_none() {
            violations.push("seed required when verdict is not skip".to_string());
        }
        if entry.get("repro_command").and_then(Value::as_str).is_none() {
            violations.push("repro_command required when verdict is not skip".to_string());
        }
    }

    // 15. Cross-validate rule_number and domain
    if let (Some(num), Some(domain)) = (
        entry.get("rule_number").and_then(Value::as_u64),
        entry.get("domain").and_then(Value::as_str),
    ) {
        let valid_range = DOMAIN_RULE_RANGES
            .iter()
            .find(|(d, _, _)| *d == domain)
            .map(|(_, lo, hi)| (*lo, *hi));
        if let Some((lo, hi)) = valid_range {
            let n = num as u32;
            if n < lo || n > hi {
                violations.push(format!(
                    "rule_number {n} is outside domain {domain:?} range [{lo}, {hi}]"
                ));
            }
        }
    }

    violations
}

// ============================================================================
// Schema Constant Tests
// ============================================================================

/// Verify the canonical rule ID count matches the contract (47 rules).
#[test]
fn schema_canonical_rule_count() {
    init_test_logging();
    assert_eq!(
        CANONICAL_RULE_IDS.len(),
        47,
        "canonical rule ID list must contain exactly 47 entries"
    );
}

/// Verify all rule IDs have valid prefix format.
#[test]
fn schema_rule_id_prefix_format() {
    init_test_logging();

    let valid_prefixes = ["rule.", "inv.", "def.", "prog.", "comb.", "law."];

    for (i, id) in CANONICAL_RULE_IDS.iter().enumerate() {
        let has_valid_prefix = valid_prefixes.iter().any(|p| id.starts_with(p));
        assert!(
            has_valid_prefix,
            "rule #{} ({id:?}) must start with one of {valid_prefixes:?}",
            i + 1
        );
    }
}

/// Verify domain ranges are contiguous and cover 1-47.
#[test]
fn schema_domain_ranges_cover_all() {
    init_test_logging();

    let mut covered = [false; 47];
    for (_, lo, hi) in DOMAIN_RULE_RANGES {
        for n in *lo..=*hi {
            covered[(n - 1) as usize] = true;
        }
    }

    for (i, c) in covered.iter().enumerate() {
        assert!(c, "rule #{} not covered by any domain range", i + 1);
    }
}

/// Verify oracle-to-rule mapping covers known oracle names.
#[test]
fn schema_oracle_mapping_valid() {
    init_test_logging();

    for (oracle_name, rule_numbers) in ORACLE_RULE_MAP {
        for &n in *rule_numbers {
            assert!(
                (1..=47).contains(&n),
                "oracle {oracle_name:?} maps to invalid rule number {n}"
            );
        }
        assert!(!oracle_name.is_empty(), "oracle name must not be empty");
    }
}

// ============================================================================
// Entry Validation Tests
// ============================================================================

/// Valid entry passes all checks.
#[test]
fn schema_valid_entry_passes() {
    init_test_logging();

    let entry = make_valid_entry();
    let violations = validate_entry(&entry);
    assert!(
        violations.is_empty(),
        "valid entry must have zero violations: {violations:?}"
    );
}

/// Missing schema_version is detected.
#[test]
fn schema_missing_version_detected() {
    init_test_logging();

    let mut entry = make_valid_entry();
    entry.as_object_mut().unwrap().remove("schema_version");
    let violations = validate_entry(&entry);
    assert!(
        violations.iter().any(|v| v.contains("schema_version")),
        "must detect missing schema_version"
    );
}

/// Wrong schema_version is detected.
#[test]
fn schema_wrong_version_detected() {
    init_test_logging();

    let mut entry = make_valid_entry();
    entry["schema_version"] = json!("sem-verification-log-v99");
    let violations = validate_entry(&entry);
    assert!(
        violations.iter().any(|v| v.contains("schema_version")),
        "must detect wrong schema_version"
    );
}

/// Invalid rule_id is detected.
#[test]
fn schema_invalid_rule_id_detected() {
    init_test_logging();

    let mut entry = make_valid_entry();
    entry["rule_id"] = json!("invalid.rule.id");
    let violations = validate_entry(&entry);
    assert!(
        violations.iter().any(|v| v.contains("rule_id")),
        "must detect invalid rule_id"
    );
}

/// Invalid evidence_class is detected.
#[test]
fn schema_invalid_evidence_class_detected() {
    init_test_logging();

    let mut entry = make_valid_entry();
    entry["evidence_class"] = json!("INVALID");
    let violations = validate_entry(&entry);
    assert!(
        violations.iter().any(|v| v.contains("evidence_class")),
        "must detect invalid evidence_class"
    );
}

/// Fail verdict without verdict_reason is detected.
#[test]
fn schema_fail_without_reason_detected() {
    init_test_logging();

    let mut entry = make_valid_entry();
    entry["verdict"] = json!("fail");
    // No verdict_reason field
    let violations = validate_entry(&entry);
    assert!(
        violations.iter().any(|v| v.contains("verdict_reason")),
        "must detect missing verdict_reason on fail"
    );
}

/// Fail verdict WITH reason passes.
#[test]
fn schema_fail_with_reason_passes() {
    init_test_logging();

    let mut entry = make_valid_entry();
    entry["verdict"] = json!("fail");
    entry["verdict_reason"] = json!("assertion failed: expected 3 got 4");
    let violations = validate_entry(&entry);
    // The only violation should NOT be about verdict_reason
    assert!(
        !violations.iter().any(|v| v.contains("verdict_reason")),
        "fail + verdict_reason should pass verdict_reason check"
    );
}

/// Skip verdict does not require seed/repro_command.
#[test]
fn schema_skip_no_seed_required() {
    init_test_logging();

    let mut entry = make_valid_entry();
    entry["verdict"] = json!("skip");
    entry.as_object_mut().unwrap().remove("seed");
    entry.as_object_mut().unwrap().remove("repro_command");
    let violations = validate_entry(&entry);
    assert!(
        !violations.iter().any(|v| v.contains("seed")),
        "skip verdict must not require seed"
    );
}

/// Non-skip verdict without seed is detected.
#[test]
fn schema_pass_without_seed_detected() {
    init_test_logging();

    let mut entry = make_valid_entry();
    entry.as_object_mut().unwrap().remove("seed");
    let violations = validate_entry(&entry);
    assert!(
        violations.iter().any(|v| v.contains("seed")),
        "pass verdict must require seed"
    );
}

/// Rule number outside domain range is detected.
#[test]
fn schema_rule_number_domain_mismatch_detected() {
    init_test_logging();

    let mut entry = make_valid_entry();
    entry["rule_number"] = json!(20); // obligation domain, but...
    entry["domain"] = json!("cancel"); // cancel domain ends at 12
    let violations = validate_entry(&entry);
    assert!(
        violations.iter().any(|v| v.contains("outside domain")),
        "must detect rule_number outside domain range"
    );
}

/// All 47 rules can be represented as valid entries.
#[test]
fn schema_all_47_rules_representable() {
    init_test_logging();

    for (i, rule_id) in CANONICAL_RULE_IDS.iter().enumerate() {
        let rule_number = (i + 1) as u32;
        let domain = DOMAIN_RULE_RANGES
            .iter()
            .find(|(_, lo, hi)| rule_number >= *lo && rule_number <= *hi)
            .map(|(d, _, _)| *d)
            .expect("rule must belong to a domain");

        let entry = json!({
            "schema_version": SCHEMA_VERSION,
            "entry_id": format!("svl-svr-test-{i:06}"),
            "run_id": "svr-test",
            "seq": i,
            "timestamp_ns": i * 1000,
            "phase": "check",
            "rule_id": rule_id,
            "rule_number": rule_number,
            "domain": domain,
            "evidence_class": "UT",
            "scenario_id": format!("rule-{rule_number}"),
            "verdict": "pass",
            "seed": 42,
            "repro_command": format!("cargo test rule_{rule_number}")
        });

        let violations = validate_entry(&entry);
        assert!(
            violations.is_empty(),
            "rule #{rule_number} ({rule_id}) must be representable: {violations:?}"
        );
    }
}

// ============================================================================
// Summary Schema Tests
// ============================================================================

/// Validate summary schema structure.
#[test]
fn summary_schema_structure() {
    init_test_logging();

    let summary = json!({
        "schema_version": SUMMARY_SCHEMA_VERSION,
        "run_id": "svr-000000000000002a-0000000000000001",
        "seed": 42,
        "timestamp": "2026-03-02T09:00:00Z",
        "commit_hash": "abc123",
        "total_entries": 47,
        "verdicts": {
            "pass": 45,
            "fail": 0,
            "skip": 2,
            "error": 0
        },
        "coverage": {
            "rules_tested": 45,
            "rules_total": 47
        }
    });

    assert_eq!(
        summary["schema_version"].as_str().unwrap(),
        SUMMARY_SCHEMA_VERSION
    );
    assert_eq!(summary["verdicts"]["pass"].as_u64().unwrap(), 45);
    assert_eq!(summary["coverage"]["rules_total"].as_u64().unwrap(), 47);

    // Verdict counts must sum to total_entries
    let total: u64 = ["pass", "fail", "skip", "error"]
        .iter()
        .map(|k| summary["verdicts"][k].as_u64().unwrap())
        .sum();
    assert_eq!(
        total,
        summary["total_entries"].as_u64().unwrap(),
        "verdict counts must sum to total_entries"
    );
}

/// Verify domain coverage sums to 47.
#[test]
fn summary_domain_coverage_sums_to_47() {
    init_test_logging();

    let total: u32 = DOMAIN_RULE_RANGES
        .iter()
        .map(|(_, lo, hi)| hi - lo + 1)
        .sum();
    assert_eq!(total, 47, "domain rule ranges must cover exactly 47 rules");
}

// ============================================================================
// JSON Round-Trip Tests
// ============================================================================

/// Entry round-trips through JSON serialization.
#[test]
fn schema_entry_json_round_trip() {
    init_test_logging();

    let entry = make_valid_entry();
    let json_str = serde_json::to_string(&entry).expect("serialize");
    let deserialized: Value = serde_json::from_str(&json_str).expect("deserialize");

    assert_eq!(entry, deserialized, "entry must round-trip through JSON");
}

/// NDJSON format: multiple entries separated by newlines.
#[test]
fn schema_ndjson_format() {
    init_test_logging();

    let entry1 = make_valid_entry();
    let mut entry2 = make_valid_entry();
    entry2["seq"] = json!(2);
    entry2["entry_id"] = json!("svl-svr-000000000000002a-0000000000000001-000002");
    entry2["rule_id"] = json!("rule.cancel.acknowledge");
    entry2["rule_number"] = json!(2);

    let ndjson = format!(
        "{}\n{}\n",
        serde_json::to_string(&entry1).unwrap(),
        serde_json::to_string(&entry2).unwrap()
    );

    let entries: Vec<Value> = ndjson
        .lines()
        .filter(|l| !l.is_empty())
        .map(|l| serde_json::from_str(l).expect("parse NDJSON line"))
        .collect();

    assert_eq!(entries.len(), 2);
    for entry in &entries {
        let violations = validate_entry(entry);
        assert!(
            violations.is_empty(),
            "NDJSON entry must validate: {violations:?}"
        );
    }

    // Seq must be monotonically increasing
    let seq1 = entries[0]["seq"].as_u64().unwrap();
    let seq2 = entries[1]["seq"].as_u64().unwrap();
    assert!(
        seq2 > seq1,
        "seq must be monotonically increasing in NDJSON"
    );
}
