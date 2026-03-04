//! Contract tests for [T8.8] Capability-Security and Authority-Flow Audit
//!
//! Validates that the capability-security audit document and JSON artifact
//! correctly describe the authority-flow compliance of TOKIO-REPLACE surfaces.
//!
//! Categories:
//! - CSA-01..CSA-15: Contract/structural validation
//! - AF-01..AF-06: Authority flow verification
//! - BI-01..BI-04: Boundary integrity checks
//! - IC-01..IC-05: Invariant coverage verification
//! - DD-01..DD-03: Drift detection rule checks

// ── Common test infrastructure ────────────────────────────────────────

mod common {
    use std::collections::HashSet;

    pub const DOC_MD: &str = include_str!("../docs/tokio_capability_security_authority_audit.md");
    pub const DOC_JSON: &str =
        include_str!("../docs/tokio_capability_security_authority_audit.json");

    pub fn json() -> serde_json::Value {
        serde_json::from_str(DOC_JSON).expect("JSON artifact must parse")
    }

    pub fn md_has_section(heading: &str) -> bool {
        // Sections may be numbered (e.g., "## 1. Scope") or unnumbered
        for line in DOC_MD.lines() {
            let trimmed = line.trim();
            if (trimmed.starts_with("## ") || trimmed.starts_with("### "))
                && trimmed.contains(heading)
            {
                return true;
            }
        }
        false
    }

    pub fn md_has_table_with(text: &str) -> bool {
        for line in DOC_MD.lines() {
            if line.starts_with('|') && line.contains(text) {
                return true;
            }
        }
        false
    }

    pub fn json_array_len(val: &serde_json::Value, key: &str) -> usize {
        val.get(key)
            .and_then(|v| v.as_array())
            .map_or(0, std::vec::Vec::len)
    }

    pub fn json_str(val: &serde_json::Value, key: &str) -> String {
        val.get(key)
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string()
    }

    pub fn unique_ids(val: &serde_json::Value, array_key: &str, id_key: &str) -> HashSet<String> {
        val.get(array_key)
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|item| item.get(id_key).and_then(|v| v.as_str()))
                    .map(ToString::to_string)
                    .collect()
            })
            .unwrap_or_default()
    }
}

// ── CSA: Contract/Structural Validation ───────────────────────────────

#[test]
fn csa_01_doc_exists_and_is_substantial() {
    assert!(
        common::DOC_MD.len() > 3000,
        "Markdown doc must be substantial (got {} bytes)",
        common::DOC_MD.len()
    );
}

#[test]
fn csa_02_json_parses_and_has_bead_id() {
    let j = common::json();
    assert_eq!(common::json_str(&j, "bead_id"), "asupersync-2oh2u.10.8");
}

#[test]
fn csa_03_doc_references_correct_bead() {
    assert!(common::DOC_MD.contains("asupersync-2oh2u.10.8"));
    assert!(common::DOC_MD.contains("[T8.8]"));
}

#[test]
fn csa_04_doc_has_required_sections() {
    let required = [
        "Scope",
        "Audit Methodology",
        "Per-Track Authority Analysis",
        "Global State Patterns",
        "Crate Boundary Integrity",
        "Invariant Compliance Matrix",
        "Advisory Findings",
        "Test Evidence",
        "Drift Detection",
    ];
    for section in &required {
        assert!(
            common::md_has_section(section),
            "Missing required section: '{section}'"
        );
    }
}

#[test]
fn csa_05_json_has_all_tracks() {
    let j = common::json();
    let tracks = j
        .get("per_track_verdicts")
        .and_then(|v| v.as_array())
        .expect("per_track_verdicts array");
    let track_ids: Vec<String> = tracks
        .iter()
        .filter_map(|t| t.get("track").and_then(|v| v.as_str()))
        .map(ToString::to_string)
        .collect();
    for expected in &["T2", "T3", "T4", "T5", "T6", "T7"] {
        assert!(
            track_ids.contains(&expected.to_string()),
            "Missing track: {expected}"
        );
    }
}

#[test]
fn csa_06_all_track_verdicts_compliant() {
    let j = common::json();
    let tracks = j
        .get("per_track_verdicts")
        .and_then(|v| v.as_array())
        .expect("per_track_verdicts array");
    for track in tracks {
        let name = track.get("track").and_then(|v| v.as_str()).unwrap_or("?");
        let verdict = track.get("verdict").and_then(|v| v.as_str()).unwrap_or("?");
        assert_eq!(
            verdict, "COMPLIANT",
            "Track {name} verdict is '{verdict}', expected COMPLIANT"
        );
    }
}

#[test]
fn csa_07_all_invariants_pass() {
    let j = common::json();
    let invariants = j
        .get("invariants_audited")
        .and_then(|v| v.as_array())
        .expect("invariants_audited array");
    assert!(invariants.len() >= 5, "Must audit at least 5 invariants");
    for inv in invariants {
        let id = inv.get("id").and_then(|v| v.as_str()).unwrap_or("?");
        let verdict = inv.get("verdict").and_then(|v| v.as_str()).unwrap_or("?");
        assert_eq!(
            verdict, "PASS",
            "Invariant {id} verdict is '{verdict}', expected PASS"
        );
    }
}

#[test]
fn csa_08_no_violations_in_summary() {
    let j = common::json();
    let summary = j.get("summary").expect("summary object");
    let violations = summary
        .get("violations")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(999);
    assert_eq!(violations, 0, "Expected zero violations");
}

#[test]
fn csa_09_overall_verdict_compliant() {
    let j = common::json();
    let summary = j.get("summary").expect("summary object");
    let verdict = summary
        .get("overall_verdict")
        .and_then(|v| v.as_str())
        .unwrap_or("?");
    assert_eq!(verdict, "COMPLIANT");
}

#[test]
fn csa_10_json_has_prohibited_patterns() {
    let j = common::json();
    let patterns = j
        .get("prohibited_patterns")
        .and_then(|v| v.as_array())
        .expect("prohibited_patterns array");
    assert!(
        patterns.len() >= 6,
        "Must check at least 6 prohibited patterns"
    );
    for pat in patterns {
        let status = pat.get("status").and_then(|v| v.as_str()).unwrap_or("?");
        assert_eq!(status, "clean", "Pattern {pat:?} is not clean");
    }
}

#[test]
fn csa_11_json_has_advisory_findings() {
    let j = common::json();
    let findings = j
        .get("advisory_findings")
        .and_then(|v| v.as_array())
        .expect("advisory_findings array");
    assert!(
        findings.len() >= 2,
        "Must document at least 2 advisory findings"
    );
    // All should have severity and location
    for f in findings {
        assert!(
            f.get("severity").and_then(|v| v.as_str()).is_some(),
            "Finding missing severity"
        );
        assert!(
            f.get("location").and_then(|v| v.as_str()).is_some(),
            "Finding missing location"
        );
    }
}

#[test]
fn csa_12_json_has_test_categories() {
    let j = common::json();
    let cats = j
        .get("test_categories")
        .and_then(|v| v.as_array())
        .expect("test_categories array");
    let prefixes: Vec<&str> = cats
        .iter()
        .filter_map(|c| c.get("prefix").and_then(|v| v.as_str()))
        .collect();
    for expected in &["CSA", "AF", "BI", "IC", "DD"] {
        assert!(
            prefixes.contains(expected),
            "Missing test category prefix: {expected}"
        );
    }
}

#[test]
fn csa_13_summary_metrics_consistent() {
    let j = common::json();
    let summary = j.get("summary").expect("summary object");

    let total_tracks = summary
        .get("total_tracks_audited")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(0);
    let track_verdicts = common::json_array_len(&j, "per_track_verdicts") as u64;
    assert_eq!(
        total_tracks, track_verdicts,
        "total_tracks_audited ({total_tracks}) != per_track_verdicts count ({track_verdicts})"
    );

    let total_invariants = summary
        .get("total_invariants_checked")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(0);
    let invariants_count = common::json_array_len(&j, "invariants_audited") as u64;
    assert_eq!(
        total_invariants, invariants_count,
        "total_invariants_checked ({total_invariants}) != invariants_audited count ({invariants_count})"
    );

    let total_tests = summary
        .get("total_tests")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(0);
    let cat_sum: u64 = j
        .get("test_categories")
        .and_then(serde_json::Value::as_array)
        .map_or(0, |arr| {
            arr.iter()
                .filter_map(|c| c.get("count").and_then(serde_json::Value::as_u64))
                .sum()
        });
    assert_eq!(
        total_tests, cat_sum,
        "total_tests ({total_tests}) != sum of category counts ({cat_sum})"
    );
}

#[test]
fn csa_14_doc_references_dependencies() {
    assert!(common::DOC_MD.contains("T8.5"));
    assert!(common::DOC_MD.contains("T8.6"));
}

#[test]
fn csa_15_json_has_crate_boundary() {
    let j = common::json();
    let boundary = j.get("crate_boundary").expect("crate_boundary object");
    assert_eq!(
        boundary
            .get("main_crate_tokio_dep")
            .and_then(serde_json::Value::as_bool),
        Some(false),
        "Main crate must NOT depend on tokio"
    );
    assert_eq!(
        boundary
            .get("reverse_dependency")
            .and_then(serde_json::Value::as_bool),
        Some(false),
        "No reverse dependency allowed"
    );
    assert_eq!(
        boundary.get("verdict").and_then(|v| v.as_str()),
        Some("COMPLIANT")
    );
}

// ── AF: Authority Flow Verification ───────────────────────────────────

#[test]
fn af_01_doc_covers_cx_propagation() {
    assert!(common::DOC_MD.contains("Cx"));
    assert!(
        common::DOC_MD.contains("no ambient authority")
            || common::DOC_MD.contains("No Ambient Authority")
    );
}

#[test]
fn af_02_doc_covers_adapter_entry_points() {
    assert!(common::DOC_MD.contains("block_on_sync"));
    assert!(common::DOC_MD.contains("AsupersyncExecutor"));
    assert!(common::DOC_MD.contains("TokioIo") || common::DOC_MD.contains("AsupersyncIo"));
}

#[test]
fn af_03_doc_covers_io_authority() {
    assert!(common::DOC_MD.contains("IoCap") || common::DOC_MD.contains("I/O authority"));
}

#[test]
fn af_04_doc_covers_blocking_cx_propagation() {
    assert!(
        common::DOC_MD.contains("Cx::set_current")
            || common::DOC_MD.contains("blocking Cx propagation")
            || common::DOC_MD.contains("Blocking Cx Propagation")
    );
}

#[test]
fn af_05_doc_covers_entropy_tracking() {
    assert!(
        common::DOC_MD.contains("check_ambient_entropy") || common::DOC_MD.contains("getrandom")
    );
}

#[test]
fn af_06_global_state_audit_clean() {
    let j = common::json();
    let gs = j
        .get("global_state_audit")
        .expect("global_state_audit object");
    let verdict = gs.get("verdict").and_then(|v| v.as_str()).unwrap_or("?");
    assert_eq!(verdict, "CLEAN");
    // All counts should be zero
    for key in &[
        "static_mut",
        "thread_local_production",
        "lazy_static",
        "once_cell_lazy",
        "cx_current_ambient",
        "tokio_spawn",
    ] {
        let count = gs
            .get(*key)
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(999);
        assert_eq!(count, 0, "Global state pattern '{key}' count should be 0");
    }
}

// ── BI: Boundary Integrity ────────────────────────────────────────────

#[test]
fn bi_01_doc_covers_crate_boundary() {
    assert!(common::md_has_section("Crate Boundary Integrity"));
}

#[test]
fn bi_02_doc_covers_feature_flags() {
    assert!(common::DOC_MD.contains("tokio-io"));
    assert!(common::DOC_MD.contains("hyper-bridge"));
}

#[test]
fn bi_03_no_tokio_in_main_cargo() {
    let cargo_toml = include_str!("../Cargo.toml");
    // Main crate should not have a direct tokio dependency
    // (it may appear in dev-dependencies or feature-gated optional deps)
    let in_deps = cargo_toml
        .lines()
        .skip_while(|l| !l.starts_with("[dependencies]"))
        .skip(1)
        .take_while(|l| !l.starts_with('['))
        .any(|l| l.starts_with("tokio"));
    assert!(
        !in_deps,
        "Main crate Cargo.toml must not have tokio in [dependencies]"
    );
}

#[test]
fn bi_04_compat_crate_exists() {
    let compat_cargo = include_str!("../asupersync-tokio-compat/Cargo.toml");
    assert!(compat_cargo.contains("asupersync-tokio-compat"));
}

// ── IC: Invariant Coverage ────────────────────────────────────────────

#[test]
fn ic_01_doc_covers_inv1_no_ambient_authority() {
    assert!(common::md_has_table_with("INV-1"));
    assert!(common::DOC_MD.contains("No Ambient Authority"));
}

#[test]
fn ic_02_doc_covers_inv2_structured_concurrency() {
    assert!(common::md_has_table_with("INV-2"));
    assert!(common::DOC_MD.contains("Structured Concurrency"));
}

#[test]
fn ic_03_doc_covers_inv3_cancellation_protocol() {
    assert!(common::md_has_table_with("INV-3"));
    assert!(common::DOC_MD.contains("Cancellation"));
}

#[test]
fn ic_04_doc_covers_inv4_no_obligation_leaks() {
    assert!(common::md_has_table_with("INV-4"));
    assert!(
        common::DOC_MD.contains("Obligation Leaks") || common::DOC_MD.contains("obligation leaks")
    );
}

#[test]
fn ic_05_doc_covers_inv5_outcome_severity() {
    assert!(common::md_has_table_with("INV-5"));
    assert!(
        common::DOC_MD.contains("Outcome Severity") || common::DOC_MD.contains("outcome severity")
    );
}

// ── DD: Drift Detection ──────────────────────────────────────────────

#[test]
fn dd_01_json_has_drift_rules() {
    let j = common::json();
    let rules = j
        .get("drift_detection")
        .and_then(|v| v.as_array())
        .expect("drift_detection array");
    assert!(
        rules.len() >= 3,
        "Must have at least 3 drift detection rules"
    );
}

#[test]
fn dd_02_drift_rule_ids_unique() {
    let j = common::json();
    let ids = common::unique_ids(&j, "drift_detection", "id");
    let rules = common::json_array_len(&j, "drift_detection");
    assert_eq!(ids.len(), rules, "Drift rule IDs must be unique");
}

#[test]
fn dd_03_drift_rules_have_trigger_and_action() {
    let j = common::json();
    let rules = j
        .get("drift_detection")
        .and_then(|v| v.as_array())
        .expect("drift_detection array");
    for rule in rules {
        assert!(
            rule.get("trigger").and_then(|v| v.as_str()).is_some(),
            "Drift rule missing trigger"
        );
        assert!(
            rule.get("action").and_then(|v| v.as_str()).is_some(),
            "Drift rule missing action"
        );
    }
}
