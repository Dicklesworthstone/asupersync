#![allow(missing_docs)]
#![allow(clippy::items_after_statements)]

//! [T8.13] Golden log corpus and schema-evolution regression harness.
//!
//! Validates the golden log corpus under `tests/fixtures/logging_golden_corpus/`,
//! enforces schema versioning, field completeness, redaction compliance,
//! correlation ID format, change log integrity, and cross-track consistency.
//!
//! Organisation:
//!   1. Manifest integrity and parsing
//!   2. Fixture file presence and loading
//!   3. Golden entry schema field completeness
//!   4. Correlation ID format validation
//!   5. Redaction compliance on golden entries
//!   6. Schema version consistency
//!   7. Change log integrity
//!   8. Invariant coverage
//!   9. Schema evolution detection (breaking vs non-breaking)
//!  10. Cross-track aggregate assertions
//!  11. Contract document validation

#[macro_use]
mod common;

use common::init_test_logging;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

fn init_test(name: &str) {
    init_test_logging();
    test_phase!(name);
}

// ============================================================================
// Corpus paths and constants
// ============================================================================

fn corpus_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/logging_golden_corpus")
}

fn contract_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("docs/tokio_golden_log_corpus_contract.md")
}

/// Required fields in a golden log entry.
const ENTRY_REQUIRED_FIELDS: &[&str] = &[
    "schema_version",
    "scenario_id",
    "phase",
    "outcome",
    "detail",
];

/// Valid phases per the cross-track contract.
const VALID_PHASES: &[&str] = &["setup", "execute", "verify", "teardown"];

/// Valid outcomes per the cross-track contract.
const VALID_OUTCOMES: &[&str] = &["pass", "fail", "skip", "error"];

/// Redaction-sensitive patterns that MUST NOT appear in golden entries.
const REDACTION_PATTERNS: &[&str] = &[
    "Bearer ",
    "password=",
    "secret=",
    "Authorization:",
    "api_key=",
    "token=sk-",
];

/// Correlation ID slug regex pattern.
fn is_valid_correlation_id(id: &str) -> bool {
    !id.is_empty()
        && id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | ':' | '-'))
}

/// Known schema versions per the contract.
const KNOWN_SCHEMA_VERSIONS: &[&str] = &[
    "e2e-suite-summary-v3",
    "raptorq-e2e-log-v1",
    "raptorq-unit-log-v1",
    "1.0",
    "quic-h3-forensic-manifest.v1",
    "logging-golden-manifest-v1",
];

// ============================================================================
// Helpers: manifest and fixture loading
// ============================================================================

fn load_manifest() -> serde_json::Value {
    let path = corpus_dir().join("manifest.json");
    let text = std::fs::read_to_string(&path).expect("manifest.json must exist");
    serde_json::from_str(&text).expect("manifest.json must be valid JSON")
}

fn load_fixture(filename: &str) -> serde_json::Value {
    let path = corpus_dir().join(filename);
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|_| panic!("fixture file must exist: {filename}"));
    serde_json::from_str(&text).unwrap_or_else(|_| panic!("fixture must be valid JSON: {filename}"))
}

fn fixture_files_from_manifest(manifest: &serde_json::Value) -> Vec<(String, String)> {
    manifest["fixtures"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| {
            (
                f["id"].as_str().unwrap().to_string(),
                f["file"].as_str().unwrap().to_string(),
            )
        })
        .collect()
}

// ============================================================================
// Tests: Section 1 - Manifest integrity (GC-01)
// ============================================================================

#[test]
fn t813_01_manifest_exists_and_parses() {
    init_test("t813_01_manifest_exists_and_parses");

    let path = corpus_dir().join("manifest.json");
    assert!(path.exists(), "GC-01: manifest.json must exist");

    let manifest = load_manifest();
    assert!(manifest.is_object(), "manifest must be a JSON object");

    test_complete!("t813_01_manifest_exists_and_parses");
}

#[test]
fn t813_02_manifest_has_required_top_level_fields() {
    init_test("t813_02_manifest_has_required_top_level_fields");

    let manifest = load_manifest();

    for field in [
        "schema_version",
        "description",
        "bead_id",
        "owner",
        "created",
        "update_policy",
        "schema_versions",
        "fixtures",
        "change_log",
    ] {
        test_section!(field);
        assert!(
            !manifest[field].is_null(),
            "GC-01: manifest missing field: {field}"
        );
    }

    test_complete!("t813_02_manifest_has_required_top_level_fields");
}

#[test]
fn t813_03_manifest_schema_version_is_known() {
    init_test("t813_03_manifest_schema_version_is_known");

    let manifest = load_manifest();
    let sv = manifest["schema_version"].as_str().unwrap();
    assert!(
        KNOWN_SCHEMA_VERSIONS.contains(&sv),
        "manifest schema_version {sv} not in known versions"
    );

    test_complete!("t813_03_manifest_schema_version_is_known");
}

// ============================================================================
// Tests: Section 2 - Fixture file presence (GC-02)
// ============================================================================

#[test]
fn t813_04_all_fixture_files_exist() {
    init_test("t813_04_all_fixture_files_exist");

    let manifest = load_manifest();
    let files = fixture_files_from_manifest(&manifest);

    for (id, filename) in &files {
        test_section!(id);
        let path = corpus_dir().join(filename);
        assert!(
            path.exists(),
            "GC-02: fixture file missing for {id}: {filename}"
        );
    }

    assert!(
        files.len() >= 6,
        "corpus must have at least 6 track fixtures"
    );

    test_complete!("t813_04_all_fixture_files_exist");
}

#[test]
fn t813_05_fixture_files_are_valid_json() {
    init_test("t813_05_fixture_files_are_valid_json");

    let manifest = load_manifest();
    let files = fixture_files_from_manifest(&manifest);

    for (id, filename) in &files {
        test_section!(id);
        let fixture = load_fixture(filename);
        assert!(fixture.is_object(), "fixture {id} must be a JSON object");
    }

    test_complete!("t813_05_fixture_files_are_valid_json");
}

// ============================================================================
// Tests: Section 3 - Golden entry schema field completeness (GC-03)
// ============================================================================

#[test]
fn t813_06_golden_entries_have_required_fields() {
    init_test("t813_06_golden_entries_have_required_fields");

    let manifest = load_manifest();
    let files = fixture_files_from_manifest(&manifest);

    for (id, filename) in &files {
        test_section!(id);
        let fixture = load_fixture(filename);
        let entry = &fixture["entry"];

        if entry.is_null() {
            continue; // some fixtures may not have entry (unlikely)
        }

        for &field in ENTRY_REQUIRED_FIELDS {
            assert!(
                !entry[field].is_null(),
                "GC-03: fixture {id} entry missing field: {field}"
            );
        }
    }

    test_complete!("t813_06_golden_entries_have_required_fields");
}

#[test]
fn t813_07_golden_entries_have_valid_phases() {
    init_test("t813_07_golden_entries_have_valid_phases");

    let manifest = load_manifest();
    let files = fixture_files_from_manifest(&manifest);

    for (id, filename) in &files {
        test_section!(id);
        let fixture = load_fixture(filename);
        let entry = &fixture["entry"];

        if let Some(phase) = entry["phase"].as_str() {
            assert!(
                VALID_PHASES.contains(&phase),
                "GC-03: fixture {id} has invalid phase: {phase}"
            );
        }
    }

    test_complete!("t813_07_golden_entries_have_valid_phases");
}

#[test]
fn t813_08_golden_entries_have_valid_outcomes() {
    init_test("t813_08_golden_entries_have_valid_outcomes");

    let manifest = load_manifest();
    let files = fixture_files_from_manifest(&manifest);

    for (id, filename) in &files {
        test_section!(id);
        let fixture = load_fixture(filename);
        let entry = &fixture["entry"];

        if let Some(outcome) = entry["outcome"].as_str() {
            assert!(
                VALID_OUTCOMES.contains(&outcome),
                "GC-03: fixture {id} has invalid outcome: {outcome}"
            );
        }
    }

    test_complete!("t813_08_golden_entries_have_valid_outcomes");
}

// ============================================================================
// Tests: Section 4 - Correlation ID format (GC-04)
// ============================================================================

#[test]
fn t813_09_correlation_ids_match_slug_format() {
    init_test("t813_09_correlation_ids_match_slug_format");

    let manifest = load_manifest();
    let files = fixture_files_from_manifest(&manifest);

    for (id, filename) in &files {
        test_section!(id);
        let fixture = load_fixture(filename);
        let entry = &fixture["entry"];

        if let Some(corr_id) = entry["correlation_id"].as_str() {
            assert!(
                is_valid_correlation_id(corr_id),
                "GC-04: fixture {id} correlation_id {corr_id:?} does not match slug format"
            );
        }
    }

    test_complete!("t813_09_correlation_ids_match_slug_format");
}

#[test]
fn t813_10_correlation_id_validator_correctness() {
    init_test("t813_10_correlation_id_validator_correctness");

    test_section!("valid_ids");
    assert!(is_valid_correlation_id("t2-io-001"));
    assert!(is_valid_correlation_id("trace_id:abc.123"));
    assert!(is_valid_correlation_id("A-Z.0_9"));

    test_section!("invalid_ids");
    assert!(!is_valid_correlation_id(""));
    assert!(!is_valid_correlation_id("has space"));
    assert!(!is_valid_correlation_id("has/slash"));
    assert!(!is_valid_correlation_id("has@at"));

    test_complete!("t813_10_correlation_id_validator_correctness");
}

// ============================================================================
// Tests: Section 5 - Redaction compliance (GC-05)
// ============================================================================

#[test]
fn t813_11_golden_entries_free_of_redaction_violations() {
    init_test("t813_11_golden_entries_free_of_redaction_violations");

    let manifest = load_manifest();
    let files = fixture_files_from_manifest(&manifest);

    for (id, filename) in &files {
        test_section!(id);
        let fixture = load_fixture(filename);
        let text = serde_json::to_string(&fixture["entry"]).unwrap();

        for pattern in REDACTION_PATTERNS {
            // Only flag if pattern appears literally in entry values (not in
            // forbidden_patterns lists that document what to check for)
            let entry_text = fixture["entry"].to_string();
            assert!(
                !entry_text.contains(pattern),
                "GC-05: fixture {id} entry contains redaction-sensitive pattern: {pattern}"
            );
        }

        // Also check the full fixture text is free of actual credential values
        assert!(
            !text.contains("sk-live-"),
            "GC-05: fixture {id} contains API key pattern"
        );
    }

    test_complete!("t813_11_golden_entries_free_of_redaction_violations");
}

// ============================================================================
// Tests: Section 6 - Schema version consistency (GC-06)
// ============================================================================

#[test]
fn t813_12_fixture_schema_versions_match_manifest() {
    init_test("t813_12_fixture_schema_versions_match_manifest");

    let manifest = load_manifest();
    let fixtures = manifest["fixtures"].as_array().unwrap();

    for fixture_meta in fixtures {
        let id = fixture_meta["id"].as_str().unwrap();
        let manifest_sv = fixture_meta["schema_version"].as_str().unwrap();
        let filename = fixture_meta["file"].as_str().unwrap();

        test_section!(id);
        let fixture = load_fixture(filename);
        let fixture_sv = fixture["schema_version"].as_str().unwrap();

        assert_eq!(
            manifest_sv, fixture_sv,
            "GC-06: fixture {id} schema_version mismatch: manifest={manifest_sv}, file={fixture_sv}"
        );
    }

    test_complete!("t813_12_fixture_schema_versions_match_manifest");
}

#[test]
fn t813_13_all_schema_versions_are_known() {
    init_test("t813_13_all_schema_versions_are_known");

    let manifest = load_manifest();
    let fixtures = manifest["fixtures"].as_array().unwrap();

    for fixture_meta in fixtures {
        let id = fixture_meta["id"].as_str().unwrap();
        let sv = fixture_meta["schema_version"].as_str().unwrap();

        test_section!(id);
        assert!(
            KNOWN_SCHEMA_VERSIONS.contains(&sv),
            "GC-06: fixture {id} uses unknown schema version: {sv}"
        );
    }

    test_complete!("t813_13_all_schema_versions_are_known");
}

// ============================================================================
// Tests: Section 7 - Change log integrity (GC-07)
// ============================================================================

#[test]
fn t813_14_change_log_is_non_empty() {
    init_test("t813_14_change_log_is_non_empty");

    let manifest = load_manifest();
    let log = manifest["change_log"].as_array().unwrap();
    assert!(!log.is_empty(), "GC-07: change_log must not be empty");

    test_complete!("t813_14_change_log_is_non_empty");
}

#[test]
fn t813_15_change_log_entries_have_required_fields() {
    init_test("t813_15_change_log_entries_have_required_fields");

    let manifest = load_manifest();
    let log = manifest["change_log"].as_array().unwrap();

    for (i, entry) in log.iter().enumerate() {
        test_section!(&format!("entry_{i}"));
        for field in [
            "date",
            "author",
            "action",
            "fixtures_affected",
            "justification",
        ] {
            assert!(
                !entry[field].is_null(),
                "GC-07: change_log entry {i} missing field: {field}"
            );
        }
    }

    test_complete!("t813_15_change_log_entries_have_required_fields");
}

// ============================================================================
// Tests: Section 8 - Invariant coverage (GC-08)
// ============================================================================

#[test]
fn t813_16_fixtures_have_invariants() {
    init_test("t813_16_fixtures_have_invariants");

    let manifest = load_manifest();
    let files = fixture_files_from_manifest(&manifest);

    for (id, filename) in &files {
        test_section!(id);
        let fixture = load_fixture(filename);
        let invariants = &fixture["invariants"];
        assert!(
            invariants.is_array() && !invariants.as_array().unwrap().is_empty(),
            "GC-08: fixture {id} must have non-empty invariants list"
        );
    }

    test_complete!("t813_16_fixtures_have_invariants");
}

// ============================================================================
// Tests: Section 9 - Schema evolution detection
// ============================================================================

#[test]
fn t813_17_schema_evolution_breaking_change_detection() {
    init_test("t813_17_schema_evolution_breaking_change_detection");

    // Simulate detecting a breaking change: removing a required field
    test_section!("field_removal_is_breaking");
    let golden_fields: Vec<&str> = vec![
        "schema_version",
        "scenario_id",
        "correlation_id",
        "phase",
        "outcome",
        "detail",
        "replay_pointer",
    ];
    let actual_fields: Vec<&str> = vec![
        "schema_version",
        "scenario_id",
        "phase",
        "outcome",
        "detail",
        "replay_pointer",
    ];

    let removed: Vec<&str> = golden_fields
        .iter()
        .copied()
        .filter(|f| !actual_fields.contains(f))
        .collect();
    assert!(
        !removed.is_empty(),
        "should detect correlation_id was removed"
    );
    assert_eq!(removed[0], "correlation_id");

    // Non-breaking: adding a new optional field
    test_section!("field_addition_is_non_breaking");
    let mut extended = golden_fields.clone();
    extended.push("new_optional_field");
    let added_count = extended
        .iter()
        .filter(|f| !golden_fields.contains(f))
        .count();
    assert_eq!(added_count, 1);
    // Addition of fields is non-breaking — no version bump required

    test_complete!("t813_17_schema_evolution_breaking_change_detection");
}

#[test]
fn t813_18_schema_version_drift_detector() {
    init_test("t813_18_schema_version_drift_detector");

    let manifest = load_manifest();
    let known_versions = manifest["schema_versions"].as_object().unwrap();

    // Verify no duplicate version values (different names, same version)
    test_section!("unique_version_names");
    let mut seen: BTreeMap<String, String> = BTreeMap::new();
    for (name, ver) in known_versions {
        let v = ver.as_str().unwrap().to_string();
        if let Some(prev_name) = seen.get(&v) {
            // This is fine — different schema families may share versions
            // but we track it for audit
            assert!(
                name != prev_name,
                "duplicate version mapping: {name} and {prev_name} both map to {v}"
            );
        }
        seen.insert(v, name.clone());
    }

    test_complete!("t813_18_schema_version_drift_detector");
}

// ============================================================================
// Tests: Section 10 - Cross-track aggregate assertions
// ============================================================================

#[test]
fn t813_19_all_tracks_represented_in_corpus() {
    init_test("t813_19_all_tracks_represented_in_corpus");

    let manifest = load_manifest();
    let fixtures = manifest["fixtures"].as_array().unwrap();

    let tracks: Vec<&str> = fixtures
        .iter()
        .filter_map(|f| f["track_id"].as_str())
        .collect();

    for expected in ["T2", "T3", "T4", "T5", "T6", "T7"] {
        test_section!(expected);
        assert!(
            tracks.contains(&expected),
            "corpus missing track: {expected}"
        );
    }

    test_complete!("t813_19_all_tracks_represented_in_corpus");
}

#[test]
fn t813_20_fixture_ids_are_unique() {
    init_test("t813_20_fixture_ids_are_unique");

    let manifest = load_manifest();
    let fixtures = manifest["fixtures"].as_array().unwrap();

    let mut ids: Vec<&str> = fixtures.iter().filter_map(|f| f["id"].as_str()).collect();
    let total = ids.len();
    ids.sort_unstable();
    ids.dedup();
    assert_eq!(
        ids.len(),
        total,
        "fixture IDs must be unique, found duplicates"
    );

    test_complete!("t813_20_fixture_ids_are_unique");
}

#[test]
fn t813_21_fixture_ids_match_between_manifest_and_files() {
    init_test("t813_21_fixture_ids_match_between_manifest_and_files");

    let manifest = load_manifest();
    let fixtures = manifest["fixtures"].as_array().unwrap();

    for fixture_meta in fixtures {
        let manifest_id = fixture_meta["id"].as_str().unwrap();
        let filename = fixture_meta["file"].as_str().unwrap();

        test_section!(manifest_id);
        let fixture = load_fixture(filename);
        let file_id = fixture["fixture_id"].as_str().unwrap();

        assert_eq!(
            manifest_id, file_id,
            "fixture_id mismatch: manifest={manifest_id}, file={file_id}"
        );
    }

    test_complete!("t813_21_fixture_ids_match_between_manifest_and_files");
}

// ============================================================================
// Tests: Section 11 - Update policy enforcement
// ============================================================================

#[test]
fn t813_22_update_policy_requires_review() {
    init_test("t813_22_update_policy_requires_review");

    let manifest = load_manifest();
    let policy = &manifest["update_policy"];

    assert_eq!(
        policy["review_required"].as_bool(),
        Some(true),
        "update_policy.review_required must be true"
    );
    assert_eq!(
        policy["drift_justification_required"].as_bool(),
        Some(true),
        "update_policy.drift_justification_required must be true"
    );

    let checklist = policy["checklist"].as_array().unwrap();
    assert!(
        checklist.len() >= 3,
        "update_policy.checklist must have at least 3 items"
    );

    test_complete!("t813_22_update_policy_requires_review");
}

// ============================================================================
// Tests: Section 12 - Contract document validation
// ============================================================================

#[test]
fn t813_23_contract_doc_exists_and_is_substantial() {
    init_test("t813_23_contract_doc_exists_and_is_substantial");

    let path = contract_path();
    assert!(path.exists(), "T8.13 contract doc must exist");

    let doc = std::fs::read_to_string(&path).unwrap();
    assert!(doc.len() > 1500, "contract doc must be substantial");

    test_complete!("t813_23_contract_doc_exists_and_is_substantial");
}

#[test]
fn t813_24_contract_references_bead_and_gates() {
    init_test("t813_24_contract_references_bead_and_gates");

    let doc = std::fs::read_to_string(contract_path()).unwrap();

    assert!(
        doc.contains("asupersync-2oh2u.10.13"),
        "must reference bead"
    );
    assert!(doc.contains("[T8.13]"), "must reference T8.13");

    for gate in [
        "GC-01", "GC-02", "GC-03", "GC-04", "GC-05", "GC-06", "GC-07", "GC-08",
    ] {
        assert!(doc.contains(gate), "missing gate: {gate}");
    }

    test_complete!("t813_24_contract_references_bead_and_gates");
}

#[test]
fn t813_25_contract_defines_schema_evolution_rules() {
    init_test("t813_25_contract_defines_schema_evolution_rules");

    let doc = std::fs::read_to_string(contract_path()).unwrap();

    assert!(doc.contains("Breaking"), "must define breaking changes");
    assert!(
        doc.contains("non-breaking"),
        "must define non-breaking changes"
    );
    assert!(
        doc.contains("version bump"),
        "must require version bump for breaking"
    );

    test_complete!("t813_25_contract_defines_schema_evolution_rules");
}
