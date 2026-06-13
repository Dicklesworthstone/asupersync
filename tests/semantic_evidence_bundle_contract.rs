//! SEM-09.2 evidence bundle contract tests.
//!
//! Validates deterministic schema, rule traceability, and owner-bead mapping
//! for missing evidence entries.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::Value;

const FIXTURE_DIR: &str = "tests/fixtures/semantic_evidence_bundle";
const SCRIPT_PATH: &str = "scripts/build_semantic_evidence_bundle.sh";
const REPORT_FIXTURE: &str = "verification_report_sample.json";
const MATRIX_FIXTURE: &str = "semantic_verification_matrix_sample.md";
const GATES_FIXTURE: &str = "semantic_readiness_gates_sample.md";
const EXPECTED_FIXTURE: &str = "verification_report_sample_expected.json";
const PUBLIC_BUNDLE_ARTIFACT: &str = "artifacts/public_guarantee_semantic_evidence_bundles_v1.json";
const PROOF_LANE_MANIFEST: &str = "artifacts/proof_lane_manifest_v1.json";
const PROOF_STATUS_SNAPSHOT: &str = "artifacts/proof_status_snapshot_v1.json";
const README_PATH: &str = "README.md";
const SEMANTIC_BUNDLE_DOC: &str = "docs/semantic_evidence_bundle.md";

fn fixture_path(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join(FIXTURE_DIR)
        .join(name)
}

fn repo_path(relative: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(relative)
}

fn repo_json(relative: &str) -> Value {
    let raw = std::fs::read_to_string(repo_path(relative))
        .unwrap_or_else(|error| panic!("{relative}: {error}"));
    serde_json::from_str(&raw).unwrap_or_else(|error| panic!("parse {relative}: {error}"))
}

fn repo_text(relative: &str) -> String {
    std::fs::read_to_string(repo_path(relative))
        .unwrap_or_else(|error| panic!("{relative}: {error}"))
}

fn path_without_fragment(path: &str) -> &str {
    path.split_once('#').map_or(path, |(file, _)| file)
}

fn assert_repo_reference_exists(label: &str, path: &str) {
    let file_path = path_without_fragment(path);
    assert!(
        repo_path(file_path).exists(),
        "{label} must point at an existing repo path: {path}"
    );
}

fn string_set(value: &Value, label: &str) -> BTreeSet<String> {
    value
        .as_array()
        .unwrap_or_else(|| panic!("{label} must be an array"))
        .iter()
        .map(|item| {
            item.as_str()
                .unwrap_or_else(|| panic!("{label} entries must be strings"))
                .to_string()
        })
        .collect()
}

fn field_string<'a>(value: &'a Value, field: &str, label: &str) -> &'a str {
    value
        .get(field)
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("{label}.{field} must be a string"))
}

fn object_array<'a>(value: &'a Value, field: &str, label: &str) -> &'a [Value] {
    value
        .get(field)
        .and_then(Value::as_array)
        .unwrap_or_else(|| panic!("{label}.{field} must be an array"))
}

fn unique_output_path() -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock should be after unix epoch")
        .as_nanos();
    std::env::temp_dir().join(format!("semantic_evidence_bundle_{nanos}.json"))
}

fn build_bundle_output_from_fixtures() -> String {
    let output_path = unique_output_path();
    let output = Command::new("bash")
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .arg(SCRIPT_PATH)
        .arg("--report")
        .arg(fixture_path(REPORT_FIXTURE))
        .arg("--matrix")
        .arg(fixture_path(MATRIX_FIXTURE))
        .arg("--gates")
        .arg(fixture_path(GATES_FIXTURE))
        .arg("--output")
        .arg(&output_path)
        .output()
        .expect("failed to execute evidence bundle script");

    assert!(
        output.status.success(),
        "bundle script failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let raw = std::fs::read_to_string(&output_path).expect("bundle output file missing");
    let _ = std::fs::remove_file(output_path);
    raw
}

fn build_bundle_from_fixtures() -> Value {
    let raw = build_bundle_output_from_fixtures();
    serde_json::from_str(&raw).expect("bundle output must be valid JSON")
}

fn fixture_json(name: &str) -> Value {
    let raw = std::fs::read_to_string(fixture_path(name))
        .unwrap_or_else(|error| panic!("read fixture {name}: {error}"));
    serde_json::from_str(&raw).unwrap_or_else(|error| panic!("parse fixture {name}: {error}"))
}

fn fixture_text(name: &str) -> String {
    std::fs::read_to_string(fixture_path(name))
        .unwrap_or_else(|error| panic!("read fixture {name}: {error}"))
}

fn scrub_bundle_text(raw: &str) -> String {
    scrub_generated_at_lines(&scrub_string(raw))
}

fn scrub_generated_at_lines(text: &str) -> String {
    let mut scrubbed = String::new();
    for line in text.lines() {
        let trimmed = line.trim_start();
        if trimmed.starts_with("\"generated_at\":") {
            let indent_len = line.len() - trimmed.len();
            scrubbed.push_str(&line[..indent_len]);
            scrubbed.push_str("\"generated_at\": \"[generated_at]\"");
            if trimmed.ends_with(',') {
                scrubbed.push(',');
            }
        } else {
            scrubbed.push_str(line);
        }
        scrubbed.push('\n');
    }
    if !text.ends_with('\n') {
        scrubbed.pop();
    }
    scrubbed
}

fn scrub_string(text: &str) -> String {
    let repo = env!("CARGO_MANIFEST_DIR");
    let tmp = std::env::temp_dir();
    let tmp = tmp.to_string_lossy();
    let scrubbed = text.replace(repo, "$REPO").replace(tmp.as_ref(), "$TMP");
    collapse_evidence_bundle_temp_names(scrubbed)
}

fn collapse_evidence_bundle_temp_names(mut text: String) -> String {
    const MARKER: &str = "semantic_evidence_bundle_";
    const REPLACEMENT: &str = "semantic_evidence_bundle_[n].json";
    let mut search_start = 0;
    while let Some(relative_start) = text[search_start..].find(MARKER) {
        let start = search_start + relative_start;
        let mut digit_end = start + MARKER.len();
        while digit_end < text.len() && text.as_bytes()[digit_end].is_ascii_digit() {
            digit_end += 1;
        }
        if digit_end == start + MARKER.len() || !text[digit_end..].starts_with(".json") {
            search_start = digit_end;
            continue;
        }
        text.replace_range(start..digit_end + ".json".len(), REPLACEMENT);
        search_start = start + REPLACEMENT.len();
    }
    text
}

#[test]
fn bundle_schema_and_traceability_contract() {
    let bundle = build_bundle_from_fixtures();

    assert_eq!(
        bundle["schema_version"].as_str(),
        Some("semantic-evidence-bundle-v1"),
        "schema version must be pinned"
    );
    assert!(
        bundle["readiness_gates"]
            .as_array()
            .is_some_and(|g| !g.is_empty()),
        "bundle must include readiness gate projection"
    );
    assert_eq!(
        bundle["traceability"]["matrix_rule_count"].as_u64(),
        Some(4),
        "fixture matrix should project 4 rules"
    );
}

#[test]
fn bundle_output_matches_scrubbed_golden() {
    let raw = build_bundle_output_from_fixtures();
    let actual = scrub_bundle_text(&raw);
    let expected = fixture_text(EXPECTED_FIXTURE);
    let actual_json: Value =
        serde_json::from_str(&actual).expect("scrubbed bundle output must be valid JSON");
    let expected_json = fixture_json(EXPECTED_FIXTURE);

    assert_eq!(
        actual_json, expected_json,
        "semantic evidence bundle parsed golden drifted for {REPORT_FIXTURE} -> {EXPECTED_FIXTURE}"
    );
    assert_eq!(
        actual, expected,
        "semantic evidence bundle reviewed text golden drifted for {REPORT_FIXTURE} -> {EXPECTED_FIXTURE}"
    );
}

#[test]
fn matrix_missing_evidence_entries_include_owner_beads() {
    let bundle = build_bundle_from_fixtures();
    let missing = bundle["missing_evidence"]
        .as_array()
        .expect("missing_evidence must be array");

    let missing_pt = missing.iter().find(|entry| {
        entry["kind"] == "matrix_rule_requirement"
            && entry["details"]["rule_id"] == "inv.cancel.idempotence"
            && entry["details"]["required_class"] == "PT"
    });
    assert!(
        missing_pt.is_some(),
        "missing PT entry for inv.cancel.idempotence must exist"
    );
    assert_eq!(
        missing_pt.expect("checked above")["owner_bead"].as_str(),
        Some("asupersync-3cddg.12.5"),
        "PT gaps must map to SEM-12.5 owner bead"
    );

    let missing_doc = missing.iter().find(|entry| {
        entry["kind"] == "matrix_rule_requirement"
            && entry["details"]["rule_id"] == "rule.cancel.request"
            && entry["details"]["required_class"] == "DOC"
    });
    assert!(
        missing_doc.is_some(),
        "missing DOC entry for rule.cancel.request must exist"
    );
    assert_eq!(
        missing_doc.expect("checked above")["owner_bead"].as_str(),
        Some("asupersync-3cddg.12.2"),
        "DOC gaps must map to SEM-12.2 owner bead"
    );
}

#[test]
fn runner_gaps_and_rerun_contract_are_present() {
    let bundle = build_bundle_from_fixtures();
    let missing = bundle["missing_evidence"]
        .as_array()
        .expect("missing_evidence must be array");

    let golden_suite_gap = missing
        .iter()
        .find(|entry| entry["kind"] == "runner_suite" && entry["details"]["suite"] == "golden");
    assert!(
        golden_suite_gap.is_some(),
        "failed required golden suite must be surfaced as missing evidence"
    );
    assert_eq!(
        golden_suite_gap.expect("checked above")["owner_bead"].as_str(),
        Some("asupersync-3cddg.12.8"),
        "golden suite failures must map to SEM-12.8 owner bead"
    );

    let artifact_gap = missing.iter().find(|entry| {
        entry["kind"] == "runner_artifact" && entry["details"]["artifact"] == "docs_output.txt"
    });
    assert!(
        artifact_gap.is_some(),
        "missing profile artifact must be surfaced"
    );
    assert_eq!(
        artifact_gap.expect("checked above")["owner_bead"].as_str(),
        Some("asupersync-3cddg.12.11"),
        "artifact contract gaps must map to SEM-12.11 owner bead"
    );

    let rerun_commands = bundle["deterministic_rerun"]["commands"]
        .as_array()
        .expect("deterministic_rerun.commands must be array");
    assert!(
        rerun_commands
            .iter()
            .filter_map(Value::as_str)
            .any(|cmd| cmd.contains("run_semantic_verification.sh")),
        "bundle must include runner rerun command"
    );
    assert!(
        rerun_commands
            .iter()
            .filter_map(Value::as_str)
            .any(|cmd| cmd.contains("build_semantic_evidence_bundle.sh")),
        "bundle must include bundle rerun command"
    );
}

#[test]
fn public_guarantee_bundle_covers_required_guarantees_and_paths() {
    let artifact = repo_json(PUBLIC_BUNDLE_ARTIFACT);
    assert_eq!(
        artifact["schema_version"].as_str(),
        Some("public-guarantee-semantic-evidence-bundles-v1")
    );
    assert_eq!(
        artifact["bead_id"].as_str(),
        Some("asupersync-idea-wizard-fifth-wave-3gaiun.14")
    );

    let source_of_truth = artifact["source_of_truth"]
        .as_object()
        .expect("source_of_truth must be an object");
    for (field, value) in source_of_truth {
        assert_repo_reference_exists(
            &format!("source_of_truth.{field}"),
            value
                .as_str()
                .unwrap_or_else(|| panic!("source_of_truth.{field} must be a string")),
        );
    }

    let required_guarantees = string_set(
        &artifact["bundle_contract"]["required_public_guarantee_ids"],
        "required_public_guarantee_ids",
    );
    let required_fields = string_set(
        &artifact["bundle_contract"]["required_fields_per_bundle"],
        "required_fields_per_bundle",
    );
    let bundles = artifact["bundles"]
        .as_array()
        .expect("bundles must be an array");
    let actual_guarantees = bundles
        .iter()
        .map(|bundle| field_string(bundle, "guarantee_id", "bundle").to_string())
        .collect::<BTreeSet<_>>();

    assert_eq!(
        actual_guarantees, required_guarantees,
        "public guarantee bundle set must match the declared required set"
    );

    let manifest = repo_json(PROOF_LANE_MANIFEST);
    let manifest_lanes = object_array(&manifest, "lanes", "proof lane manifest")
        .iter()
        .map(|lane| field_string(lane, "lane_id", "manifest lane").to_string())
        .collect::<BTreeSet<_>>();
    let manifest_guarantees = object_array(&manifest, "guarantees", "proof lane manifest")
        .iter()
        .map(|guarantee| field_string(guarantee, "guarantee_id", "manifest guarantee").to_string())
        .collect::<BTreeSet<_>>();

    let status_snapshot = repo_json(PROOF_STATUS_SNAPSHOT);
    let status_claims = object_array(
        &status_snapshot,
        "claim_categories",
        "proof status snapshot",
    )
    .iter()
    .map(|claim| field_string(claim, "claim_id", "proof status claim").to_string())
    .collect::<BTreeSet<_>>();
    let evidence_statuses = object_array(
        &status_snapshot,
        "proof_evidence_status_catalog",
        "proof status snapshot",
    )
    .iter()
    .map(|status| field_string(status, "status", "proof evidence status").to_string())
    .collect::<BTreeSet<_>>();

    for bundle in bundles {
        let guarantee_id = field_string(bundle, "guarantee_id", "bundle");
        for field in &required_fields {
            assert!(
                bundle.get(field).is_some(),
                "{guarantee_id} must include required field {field}"
            );
        }

        for field in [
            "semantic_sources",
            "proof_lanes",
            "fixtures",
            "conformance_rows",
            "failure_mode_examples",
            "no_claim_boundaries",
            "readme_links",
        ] {
            assert!(
                !object_array(bundle, field, guarantee_id).is_empty(),
                "{guarantee_id}.{field} must not be empty"
            );
        }

        for lane in object_array(bundle, "proof_lanes", guarantee_id) {
            let lane_id = field_string(lane, "lane_id", guarantee_id);
            assert!(
                manifest_lanes.contains(lane_id),
                "{guarantee_id} references unknown manifest lane {lane_id}"
            );

            let manifest_guarantee_id = field_string(lane, "manifest_guarantee_id", guarantee_id);
            assert!(
                manifest_guarantees.contains(manifest_guarantee_id),
                "{guarantee_id} references unknown manifest guarantee {manifest_guarantee_id}"
            );

            let proof_status_claim_id = field_string(lane, "proof_status_claim_id", guarantee_id);
            assert!(
                status_claims.contains(proof_status_claim_id),
                "{guarantee_id} references unknown proof-status claim {proof_status_claim_id}"
            );

            let expected_evidence_status =
                field_string(lane, "expected_evidence_status", guarantee_id);
            assert!(
                evidence_statuses.contains(expected_evidence_status),
                "{guarantee_id} uses unknown evidence status {expected_evidence_status}"
            );
        }

        for field in [
            "semantic_sources",
            "fixtures",
            "conformance_rows",
            "failure_mode_examples",
            "readme_links",
        ] {
            for row in object_array(bundle, field, guarantee_id) {
                assert_repo_reference_exists(
                    &format!("{guarantee_id}.{field}"),
                    field_string(row, "path", guarantee_id),
                );
            }
        }

        let no_claims = object_array(bundle, "no_claim_boundaries", guarantee_id);
        assert!(
            no_claims.iter().any(|entry| {
                entry
                    .as_str()
                    .is_some_and(|text| text.starts_with("Does not "))
            }),
            "{guarantee_id} must keep explicit no-claim boundary language"
        );
    }
}

#[test]
fn public_guarantee_bundle_links_docs_and_fail_closed_fixtures() {
    let artifact = repo_json(PUBLIC_BUNDLE_ARTIFACT);
    let status_snapshot = repo_json(PROOF_STATUS_SNAPSHOT);
    let evidence_statuses = object_array(
        &status_snapshot,
        "proof_evidence_status_catalog",
        "proof status snapshot",
    )
    .iter()
    .map(|status| field_string(status, "status", "proof evidence status").to_string())
    .collect::<BTreeSet<_>>();

    let freshness = artifact["freshness_policy"]
        .as_object()
        .expect("freshness_policy must be an object");
    assert_eq!(
        freshness
            .get("status_catalog_source")
            .and_then(Value::as_str),
        Some("artifacts/proof_status_snapshot_v1.json#proof_evidence_status_catalog")
    );

    let accepted = string_set(
        freshness
            .get("accepted_statuses")
            .expect("accepted_statuses"),
        "accepted_statuses",
    );
    assert_eq!(
        accepted,
        BTreeSet::from([
            "approved-cache-hit".to_string(),
            "fresh-rch-pass".to_string()
        ])
    );

    let fail_closed = string_set(
        freshness
            .get("fail_closed_statuses")
            .expect("fail_closed_statuses"),
        "fail_closed_statuses",
    );
    for status in &fail_closed {
        assert!(
            evidence_statuses.contains(status),
            "fail-closed status {status} must exist in proof status catalog"
        );
    }
    for required in ["rerun-required", "stale-evidence", "blocked", "unsupported"] {
        assert!(
            fail_closed.contains(required),
            "freshness policy must fail closed for {required}"
        );
    }

    for path in freshness
        .get("rejection_fixture_paths")
        .and_then(Value::as_array)
        .expect("rejection_fixture_paths must be an array")
        .iter()
        .map(|item| {
            item.as_str()
                .expect("rejection_fixture_paths entries must be strings")
        })
    {
        assert_repo_reference_exists("freshness_policy.rejection_fixture_paths", path);
    }

    let readme = repo_text(README_PATH);
    let docs = repo_text(SEMANTIC_BUNDLE_DOC);
    for required in [
        PUBLIC_BUNDLE_ARTIFACT,
        "Public guarantee semantic evidence bundles",
        "no-orphan-tasks",
        "race-loser-drain",
        "no-obligation-leaks",
        "cancel-safe-send",
        "deterministic-replay",
        "default-production-no-tokio",
    ] {
        assert!(
            readme.contains(required) || docs.contains(required),
            "README or semantic evidence docs must mention {required}"
        );
    }
    assert!(
        docs.contains("public-guarantee-semantic-evidence-bundles-v1"),
        "semantic evidence docs must name the public guarantee bundle schema"
    );
}
