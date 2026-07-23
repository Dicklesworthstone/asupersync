#![allow(missing_docs)]

#[path = "../benches/golden_registry.rs"]
mod golden_registry;

use golden_registry::*;
use std::collections::BTreeMap;
use std::path::Path;

fn valid_entry() -> GoldenEntry {
    GoldenEntry {
        output_hash: "a".repeat(64),
        git_sha: "b".repeat(40),
        generated_at: "1784800000Z".into(),
    }
}

fn valid_file() -> GoldenChecksumFile {
    GoldenChecksumFile {
        schema_version: GOLDEN_SCHEMA_VERSION,
        generated_by: GOLDEN_GENERATED_BY.into(),
        checksums: StrictChecksumMap(
            GOLDEN_SCENARIOS
                .iter()
                .map(|scenario| ((*scenario).to_string(), valid_entry()))
                .collect(),
        ),
    }
}

#[test]
fn tracked_registry_is_exact_and_valid() {
    let file = load_golden_registry_from_path(Path::new(GOLDEN_CHECKSUMS_PATH))
        .expect("tracked registry must pass the benchmark's fail-closed parser");
    assert_eq!(file.checksums.0.len(), GOLDEN_SCENARIOS.len());
}

#[test]
fn missing_registry_file_is_rejected() {
    let path = Path::new("artifacts/definitely_missing_golden_checksums.json");
    let error = load_golden_registry_from_path(path).expect_err("missing registry must fail");
    assert!(error.contains("read required golden registry"), "{error}");
}

#[test]
fn missing_and_extra_scenarios_are_rejected() {
    let mut missing = valid_file();
    missing.checksums.0.remove(GOLDEN_SCENARIOS[0]);
    let error = validate_registry(&missing).expect_err("missing scenario must fail");
    assert!(error.contains("missing="), "{error}");

    let mut extra = valid_file();
    extra
        .checksums
        .0
        .insert("stale/extra".into(), valid_entry());
    let error = validate_registry(&extra).expect_err("stale extra scenario must fail");
    assert!(error.contains("extra="), "{error}");
}

#[test]
fn sentinel_and_incomplete_provenance_are_rejected() {
    let mut sentinel = valid_file();
    sentinel
        .checksums
        .0
        .get_mut(GOLDEN_SCENARIOS[0])
        .expect("scenario")
        .output_hash = "GENERATE".into();
    let error = validate_registry(&sentinel).expect_err("GENERATE must fail closed");
    assert!(error.contains("output_hash"), "{error}");

    let mut short_sha = valid_file();
    short_sha
        .checksums
        .0
        .get_mut(GOLDEN_SCENARIOS[0])
        .expect("scenario")
        .git_sha = "deadbeef".into();
    let error = validate_registry(&short_sha).expect_err("short provenance must fail");
    assert!(error.contains("40-character"), "{error}");
}

#[test]
fn duplicate_json_scenario_is_rejected() {
    let entry = serde_json::to_string(&valid_entry()).expect("serialize entry");
    let duplicate = format!(
        "{{\"schema_version\":1,\"generated_by\":\"test\",\"checksums\":{{\"duplicate\":{entry},\"duplicate\":{entry}}}}}"
    );
    let error = parse_golden_registry(&duplicate).expect_err("duplicate scenario must fail");
    assert!(
        error.contains("duplicate golden checksum scenario"),
        "{error}"
    );
}

#[test]
fn update_candidate_requires_only_the_exact_fresh_scenario_set() {
    let provenance = ReviewedProvenance {
        git_sha: "c".repeat(40),
        generated_at: "1784800001Z".into(),
    };
    let exact: BTreeMap<String, String> = GOLDEN_SCENARIOS
        .iter()
        .map(|scenario| ((*scenario).to_string(), "d".repeat(64)))
        .collect();
    let candidate = build_update_candidate(&exact, &provenance)
        .expect("complete fresh update set must produce a candidate");
    assert_eq!(candidate.checksums.0.len(), GOLDEN_SCENARIOS.len());
    assert!(
        candidate
            .checksums
            .0
            .values()
            .all(|entry| entry.git_sha == provenance.git_sha)
    );

    let mut stale = exact;
    stale.insert("stale/extra".into(), "e".repeat(64));
    let error = build_update_candidate(&stale, &provenance)
        .expect_err("update mode must not merge or preserve stale extras");
    assert!(error.contains("extra="), "{error}");
}

#[test]
fn reviewed_provenance_requires_matching_clean_commit() {
    let reviewed = "f".repeat(40);
    validate_reviewed_provenance(&reviewed, &reviewed, "")
        .expect("matching clean reviewed commit must pass");

    let error = validate_reviewed_provenance(&reviewed, &"e".repeat(40), "")
        .expect_err("mismatched HEAD must fail");
    assert!(error.contains("does not match HEAD"), "{error}");

    let error = validate_reviewed_provenance(&reviewed, &reviewed, " M src/runtime.rs")
        .expect_err("tracked dirt must fail");
    assert!(error.contains("clean tracked tree"), "{error}");
}
