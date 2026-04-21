#![allow(warnings)]
#![allow(clippy::all)]
//! SEM-10.4 mismatch-fixture harness contract checks.
//!
//! Ensures the fixture catalog and harness script stay deterministic, complete,
//! and aligned with required projection surfaces.

use std::collections::BTreeSet;
use std::path::Path;

use serde_json::Value;

const FIXTURE_FILE: &str = "tests/fixtures/semantic_guardrail_mismatch/fixtures.json";
const HARNESS_SCRIPT: &str = "scripts/test_semantic_guardrail_mismatch_fixtures.sh";

fn load_fixture_catalog() -> Value {
    let raw =
        std::fs::read_to_string(FIXTURE_FILE).expect("failed to read mismatch fixture catalog");
    serde_json::from_str(&raw).expect("failed to parse mismatch fixture catalog JSON")
}

#[test]
fn fixture_catalog_schema_and_nonempty_cases() {
    let catalog = load_fixture_catalog();

    assert_eq!(
        catalog["schema_version"].as_str(),
        Some("semantic-guardrail-mismatch-fixtures-v1"),
        "fixture schema version must be pinned"
    );

    let cases = catalog["cases"]
        .as_array()
        .expect("catalog.cases must be array");
    assert!(
        !cases.is_empty(),
        "catalog must include at least one mismatch fixture"
    );
}

#[test]
fn fixture_catalog_covers_required_projection_surfaces() {
    let catalog = load_fixture_catalog();
    let cases = catalog["cases"].as_array().expect("cases array");

    let mut surfaces = BTreeSet::new();
    for case in cases {
        if let Some(surface) = case["surface"].as_str() {
            surfaces.insert(surface.to_string());
        }
    }

    let expected = ["docs", "runtime", "lean", "tla", "e2e"];
    for surface in expected {
        assert!(
            surfaces.contains(surface),
            "fixture catalog missing required surface: {surface}"
        );
    }
}

#[test]
fn fixture_cases_require_nonzero_exit_and_actionable_diagnostics() {
    let catalog = load_fixture_catalog();
    let cases = catalog["cases"].as_array().expect("cases array");

    let allowed_ops = ["replace_first", "append_text"];

    for case in cases {
        let fixture_id = case["fixture_id"]
            .as_str()
            .expect("fixture_id must be string");

        let expected_exit = case["expected_exit"]
            .as_i64()
            .expect("expected_exit must be integer");
        assert_ne!(
            expected_exit, 0,
            "fixture {fixture_id} must expect non-zero exit for mismatch validation"
        );

        let diagnostics = case["expected_substrings"]
            .as_array()
            .expect("expected_substrings must be array");
        assert!(
            !diagnostics.is_empty(),
            "fixture {fixture_id} must assert at least one diagnostic substring"
        );

        let op = case["mutation"]["operation"]
            .as_str()
            .expect("mutation.operation must be string");
        assert!(
            allowed_ops.contains(&op),
            "fixture {fixture_id} has unsupported mutation op: {op}"
        );

        assert!(
            case["command"]
                .as_str()
                .is_some_and(|s: &str| !s.trim().is_empty()),
            "fixture {fixture_id} must include a command"
        );
    }
}

#[test]
fn harness_script_references_catalog_and_report_schema() {
    assert!(
        Path::new(HARNESS_SCRIPT).exists(),
        "harness script must exist"
    );

    let script = std::fs::read_to_string(HARNESS_SCRIPT).expect("failed to read harness script");
    assert!(
        script.contains(FIXTURE_FILE),
        "harness script must reference fixture catalog path"
    );
    assert!(
        script.contains("semantic-guardrail-mismatch-report-v1"),
        "harness script must emit deterministic summary schema"
    );
    assert!(
        script.contains("--light"),
        "harness script should support lightweight deterministic mode"
    );
}
