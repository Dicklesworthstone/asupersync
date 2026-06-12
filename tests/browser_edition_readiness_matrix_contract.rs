#![allow(missing_docs)]

use serde_json::Value as JsonValue;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

const MATRIX_PATH: &str = "artifacts/browser_edition_readiness_matrix_v1.json";
const MATRIX_DOC_PATH: &str = "docs/browser_edition_readiness_matrix.md";

fn repo_path(relative: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(relative)
}

fn read_repo_file(relative: &str) -> String {
    std::fs::read_to_string(repo_path(relative))
        .unwrap_or_else(|err| panic!("read {relative}: {err}"))
}

fn json_file(relative: &str) -> JsonValue {
    serde_json::from_str(&read_repo_file(relative))
        .unwrap_or_else(|err| panic!("parse {relative}: {err}"))
}

fn array<'a>(value: &'a JsonValue, key: &str) -> &'a Vec<JsonValue> {
    value
        .get(key)
        .and_then(JsonValue::as_array)
        .unwrap_or_else(|| panic!("{key} must be an array"))
}

fn object<'a>(value: &'a JsonValue, key: &str) -> &'a serde_json::Map<String, JsonValue> {
    value
        .get(key)
        .and_then(JsonValue::as_object)
        .unwrap_or_else(|| panic!("{key} must be an object"))
}

fn string<'a>(value: &'a JsonValue, key: &str) -> &'a str {
    value
        .get(key)
        .and_then(JsonValue::as_str)
        .unwrap_or_else(|| panic!("{key} must be a string"))
}

fn strings(value: &JsonValue, key: &str) -> Vec<String> {
    array(value, key)
        .iter()
        .map(|entry| {
            entry
                .as_str()
                .unwrap_or_else(|| panic!("{key} entries must be strings"))
                .to_string()
        })
        .collect()
}

fn string_set(value: &JsonValue, key: &str) -> BTreeSet<String> {
    strings(value, key).into_iter().collect()
}

fn normalized_contains(haystack: &str, needle: &str) -> bool {
    haystack
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .contains(needle)
}

fn matrix() -> JsonValue {
    json_file(MATRIX_PATH)
}

fn support_class_ids(matrix: &JsonValue) -> BTreeSet<String> {
    array(matrix, "support_classes")
        .iter()
        .map(|class| string(class, "class_id").to_string())
        .collect()
}

fn row_ids(matrix: &JsonValue) -> BTreeSet<String> {
    array(matrix, "rows")
        .iter()
        .map(|row| string(row, "surface_id").to_string())
        .collect()
}

fn path_exists(path: &str) -> bool {
    repo_path(path.trim_end_matches('/')).exists()
}

fn parse_date_days(date: &str) -> i64 {
    let parts = date
        .split('-')
        .map(|part| {
            part.parse::<i64>()
                .unwrap_or_else(|err| panic!("date component in {date}: {err}"))
        })
        .collect::<Vec<_>>();
    assert_eq!(parts.len(), 3, "date {date} must be YYYY-MM-DD");
    days_from_civil(parts[0], parts[1], parts[2])
}

fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let y = year - i64::from(month <= 2);
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = month + if month > 2 { -3 } else { 9 };
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

fn row_is_stale(row: &JsonValue, as_of: &str, default_window_days: u64) -> bool {
    let reviewed = string(row, "last_reviewed_date");
    let window_days = row
        .get("review_window_days")
        .and_then(JsonValue::as_u64)
        .unwrap_or(default_window_days);
    let age_days = parse_date_days(as_of) - parse_date_days(reviewed);
    age_days < 0 || age_days > window_days as i64
}

#[test]
fn matrix_declares_required_rows_support_classes_and_no_claim_boundaries() {
    let matrix = matrix();
    assert_eq!(
        matrix.get("contract_version").and_then(JsonValue::as_str),
        Some("browser-edition-readiness-matrix-v1")
    );
    assert_eq!(
        matrix.get("bead_id").and_then(JsonValue::as_str),
        Some("asupersync-idea-wizard-fifth-wave-3gaiun.4.1")
    );

    let required = string_set(&matrix, "required_surface_ids");
    assert_eq!(
        row_ids(&matrix),
        required,
        "rows must exactly cover the declared readiness surface ids"
    );

    let support_classes = support_class_ids(&matrix);
    for required_class in [
        "direct_runtime_supported",
        "package_abi_boundary",
        "preview_public_lane",
        "broker_coordinator_only",
        "bridge_only",
        "impossible_unsupported",
    ] {
        assert!(
            support_classes.contains(required_class),
            "missing support class {required_class}"
        );
    }

    for row in array(&matrix, "rows") {
        let surface_id = string(row, "surface_id");
        let support_class = string(row, "support_class");
        assert!(
            support_classes.contains(support_class),
            "{surface_id} references unknown support class {support_class}"
        );
        assert!(
            row.get("direct_runtime_allowed")
                .and_then(JsonValue::as_bool)
                .is_some(),
            "{surface_id} must declare direct_runtime_allowed"
        );
        assert!(
            !string(row, "display_name").is_empty(),
            "{surface_id} missing display_name"
        );
        assert!(
            !string(row, "canonical_package").is_empty(),
            "{surface_id} missing canonical_package"
        );

        for key in ["promotion_criteria", "demotion_criteria", "no_claims"] {
            assert!(!array(row, key).is_empty(), "{surface_id} missing {key}");
            for entry in array(row, key) {
                assert!(
                    !entry.as_str().unwrap_or_default().is_empty(),
                    "{surface_id} has empty {key} entry"
                );
            }
        }

        let rollback = object(row, "rollback_status");
        for key in ["state", "action"] {
            assert!(
                !rollback
                    .get(key)
                    .and_then(JsonValue::as_str)
                    .unwrap_or("")
                    .is_empty(),
                "{surface_id} rollback_status.{key} is required"
            );
        }

        let fixture = object(row, "required_fixture");
        let has_fixture_path = fixture.get("path").and_then(JsonValue::as_str);
        let has_fixture_exemption = fixture
            .get("fixture_not_required_reason")
            .and_then(JsonValue::as_str);
        assert!(
            has_fixture_path.is_some() || has_fixture_exemption.is_some(),
            "{surface_id} must name a required fixture or explicit exemption"
        );
        if let Some(path) = has_fixture_path {
            assert!(
                path_exists(path),
                "{surface_id} fixture path missing: {path}"
            );
        }

        assert!(
            !array(row, "evidence_lanes").is_empty(),
            "{surface_id} must cite evidence lanes"
        );
        for lane in array(row, "evidence_lanes") {
            let lane_id = string(lane, "lane_id");
            let path = string(lane, "path");
            assert!(
                path_exists(path),
                "{surface_id} evidence lane {lane_id} path missing: {path}"
            );
        }
    }
}

#[test]
fn readiness_docs_align_with_primary_browser_docs() {
    let matrix = matrix();
    let readme = read_repo_file("README.md");
    let wasm = read_repo_file("docs/WASM.md");
    let integration = read_repo_file("docs/integration.md");
    let matrix_doc = read_repo_file(MATRIX_DOC_PATH);
    let release_strategy = read_repo_file("docs/wasm_release_channel_strategy.md");

    for (doc_name, doc) in [
        ("README.md", &readme),
        ("docs/WASM.md", &wasm),
        ("docs/integration.md", &integration),
    ] {
        assert!(
            doc.contains("browser_edition_readiness_matrix_v1.json"),
            "{doc_name} must link the checked readiness matrix artifact"
        );
        assert!(
            doc.contains("docs/browser_edition_readiness_matrix.md")
                || doc.contains("./browser_edition_readiness_matrix.md")
                || doc.contains("browser_edition_readiness_matrix.md"),
            "{doc_name} must link the human readiness matrix"
        );
    }

    for class in array(&matrix, "support_classes") {
        let label = string(class, "docs_label");
        assert!(
            normalized_contains(&readme, label)
                || normalized_contains(&wasm, label)
                || normalized_contains(&integration, label)
                || normalized_contains(&release_strategy, label)
                || normalized_contains(&matrix_doc, label),
            "support class label missing from docs: {label}"
        );
    }

    for row in array(&matrix, "rows") {
        let surface_id = string(row, "surface_id");
        assert!(
            matrix_doc.contains(surface_id) || matrix_doc.contains(string(row, "display_name")),
            "matrix doc must mention {surface_id}"
        );

        let docs_markers = object(row, "docs_markers");
        for (doc_path, markers) in docs_markers {
            let doc = match doc_path.as_str() {
                "README.md" => &readme,
                "docs/WASM.md" => &wasm,
                "docs/integration.md" => &integration,
                other => panic!("{surface_id} cites unsupported docs_markers path {other}"),
            };
            for marker in markers
                .as_array()
                .unwrap_or_else(|| panic!("{surface_id} docs_markers.{doc_path} must be an array"))
            {
                let marker = marker
                    .as_str()
                    .unwrap_or_else(|| panic!("{surface_id} marker must be string"));
                assert!(
                    normalized_contains(doc, marker),
                    "{surface_id} marker {marker:?} missing from {doc_path}"
                );
            }
        }
    }
}

#[test]
fn freshness_policy_detects_stale_rows_and_requires_fail_closed_refresh() {
    let matrix = matrix();
    let policy_value = matrix
        .get("freshness_policy")
        .expect("freshness_policy object");
    let policy = object(&matrix, "freshness_policy");
    let as_of = policy
        .get("as_of_date_for_contract")
        .and_then(JsonValue::as_str)
        .expect("freshness_policy.as_of_date_for_contract");
    let max_age = policy
        .get("max_row_age_days")
        .and_then(JsonValue::as_u64)
        .expect("freshness_policy.max_row_age_days");
    assert_eq!(
        policy.get("stale_verdict").and_then(JsonValue::as_str),
        Some("stale_readiness_row")
    );

    for key in [
        "support_class",
        "evidence_lanes",
        "required_fixture",
        "rollback_status",
        "promotion_criteria",
        "demotion_criteria",
        "no_claims",
    ] {
        assert!(
            strings(policy_value, "required_refresh_fields").contains(&key.to_string()),
            "freshness policy must require {key} refresh"
        );
    }

    for row in array(&matrix, "rows") {
        assert!(
            !row_is_stale(row, as_of, max_age),
            "{} should be fresh under the contract as_of date",
            string(row, "surface_id")
        );
    }

    let mut stale = array(&matrix, "rows")[0].clone();
    stale
        .as_object_mut()
        .expect("row object")
        .insert("last_reviewed_date".to_string(), "2026-01-01".into());
    assert!(
        row_is_stale(&stale, as_of, max_age),
        "old readiness rows must be detected as stale"
    );
}

#[test]
fn validation_commands_are_bounded_and_remote_required_for_cargo_proof() {
    let matrix = matrix();
    let commands = strings(&matrix, "validation_commands");
    assert!(
        commands
            .iter()
            .any(|command| command == "jq empty artifacts/browser_edition_readiness_matrix_v1.json"),
        "matrix must keep a JSON syntax validation command"
    );
    assert!(
        commands.iter().any(|command| {
            command.contains(
                "rustfmt --edition 2024 --check tests/browser_edition_readiness_matrix_contract.rs",
            )
        }),
        "matrix must keep a local rustfmt check for the focused contract"
    );
    assert!(
        commands.iter().any(|command| {
            command.contains("RCH_REQUIRE_REMOTE=1 rch exec --")
                && command.contains(
                    "cargo test -p asupersync --test browser_edition_readiness_matrix_contract",
                )
                && command.contains("rch_target_browser_readiness_matrix")
        }),
        "Cargo proof must be a bounded RCH remote-required test lane"
    );
}
