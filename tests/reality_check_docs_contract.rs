#![allow(missing_docs)]

use serde_json::Value as JsonValue;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

const CONTRACT_PATH: &str = "artifacts/reality_check_docs_contract_v1.json";
const DIRECT_FORMAL_LEAN_BUILD_COMMAND: &str = "rch exec -- lake --dir formal/lean build";

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

fn contract() -> JsonValue {
    json_file(CONTRACT_PATH)
}

fn array<'a>(value: &'a JsonValue, key: &str) -> &'a Vec<JsonValue> {
    value
        .get(key)
        .and_then(JsonValue::as_array)
        .unwrap_or_else(|| panic!("{key} must be an array"))
}

fn nonempty_string<'a>(value: &'a JsonValue, key: &str) -> &'a str {
    let item = value
        .get(key)
        .and_then(JsonValue::as_str)
        .unwrap_or_else(|| panic!("{key} must be a string"));
    assert!(!item.trim().is_empty(), "{key} must be nonempty");
    item
}

fn string_set(value: &JsonValue, key: &str) -> BTreeSet<String> {
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

fn assert_contains(haystack: &str, needle: &str, label: &str) {
    assert!(
        haystack.contains(needle),
        "{label} must contain marker {needle:?}"
    );
}

fn assert_not_contains(haystack: &str, needle: &str, label: &str) {
    assert!(
        !haystack.contains(needle),
        "{label} must not contain stale marker {needle:?}"
    );
}

fn log_contract_event(scenario_id: &str, fields: &[(&str, String)]) {
    let mut parts = vec![
        "bead_id=asupersync-rckdoc".to_string(),
        format!("scenario_id={scenario_id}"),
    ];
    parts.extend(fields.iter().map(|(key, value)| format!("{key}={value}")));
    println!("{}", parts.join(" "));
}

fn is_full_hex_sha(value: &str) -> bool {
    value.len() == 40 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

#[test]
fn docs_contract_names_all_public_docs_artifacts_and_support_classes() {
    let contract = contract();
    assert_eq!(
        contract.get("contract_version").and_then(JsonValue::as_str),
        Some("reality-check-docs-contract-v1")
    );
    assert_eq!(
        contract.get("bead_id").and_then(JsonValue::as_str),
        Some("asupersync-rckdoc")
    );

    for path in string_set(&contract, "docs_checked") {
        assert!(repo_path(&path).is_file(), "doc path must exist: {path}");
    }

    for path in string_set(&contract, "source_artifacts_checked") {
        assert!(
            repo_path(&path).is_file(),
            "source artifact must exist: {path}"
        );
    }

    let support_classes = string_set(&contract, "support_classes_seen");
    for required in [
        "machine-checked-registry",
        "production-live",
        "production-live-opt-in",
        "fail-closed-boundary",
        "not-advertised-deferred",
        "virtual-lab-proof",
        "direct-runtime-supported",
        "guarded-direct-runtime-support",
        "direct-runtime-feasible-not-yet-shipped",
        "bridge-only",
        "impossible-unsupported",
        "checked-core-invariants",
        "tokio-free-normal-graph",
        "tokio-carrying-quarantined",
        "local-enforced-main-gates",
        "documented-deferred-surface",
        "unsupported-fail-closed",
    ] {
        assert!(
            support_classes.contains(required),
            "missing support class {required}"
        );
    }

    log_contract_event(
        "contract-inventory",
        &[
            (
                "docs_checked",
                array(&contract, "docs_checked").len().to_string(),
            ),
            (
                "source_artifacts_checked",
                array(&contract, "source_artifacts_checked")
                    .len()
                    .to_string(),
            ),
            (
                "support_classes_seen",
                array(&contract, "support_classes_seen").len().to_string(),
            ),
            ("verdict", "pass".to_string()),
            ("first_failure", String::new()),
        ],
    );
}

#[test]
fn public_docs_have_required_markers_and_no_stale_claims() {
    let contract = contract();
    for row in array(&contract, "doc_marker_contract") {
        let path = nonempty_string(row, "path");
        let text = read_repo_file(path);

        for marker in array(row, "required") {
            let marker = marker.as_str().expect("required marker string");
            assert_contains(&text, marker, path);
        }

        for marker in array(row, "forbidden") {
            let marker = marker.as_str().expect("forbidden marker string");
            assert_not_contains(&text, marker, path);
        }

        log_contract_event(
            "doc-marker-row",
            &[
                ("doc", path.to_string()),
                ("required_count", array(row, "required").len().to_string()),
                ("forbidden_count", array(row, "forbidden").len().to_string()),
                ("verdict", "pass".to_string()),
                ("first_failure", String::new()),
            ],
        );
    }
}

#[test]
fn browser_support_class_vocabulary_is_cross_doc_consistent() {
    let contract = contract();
    for row in array(&contract, "support_class_contract") {
        let support_class = nonempty_string(row, "support_class");
        nonempty_string(row, "meaning");
        for requirement in array(row, "docs_required") {
            let path = nonempty_string(requirement, "path");
            let text = read_repo_file(path);
            for marker in array(requirement, "markers") {
                let marker = marker.as_str().expect("support marker string");
                assert_contains(&text, marker, support_class);
            }
        }

        log_contract_event(
            "support-class-row",
            &[
                ("support_class", support_class.to_string()),
                (
                    "docs_required",
                    array(row, "docs_required").len().to_string(),
                ),
                ("verdict", "pass".to_string()),
                ("first_failure", String::new()),
            ],
        );
    }
}

#[test]
fn deferred_surfaces_have_artifacts_owner_beads_or_explicit_non_promotion_rationale() {
    let contract = contract();
    for row in array(&contract, "deferred_links_checked") {
        let surface_id = nonempty_string(row, "surface_id");
        let support_class = nonempty_string(row, "support_class");
        let artifact = nonempty_string(row, "artifact");
        assert!(
            repo_path(artifact).exists(),
            "{surface_id}: artifact must exist: {artifact}"
        );

        let owner_bead = row
            .get("owner_bead")
            .and_then(JsonValue::as_str)
            .unwrap_or("");
        let explanation = row
            .get("intentional_explanation")
            .and_then(JsonValue::as_str)
            .unwrap_or("");
        assert!(
            owner_bead.starts_with("asupersync-") || !explanation.trim().is_empty(),
            "{surface_id}: needs owner bead or intentional explanation"
        );

        for marker in array(row, "doc_markers") {
            let path = nonempty_string(marker, "path");
            let marker_text = nonempty_string(marker, "marker");
            let text = read_repo_file(path);
            assert_contains(&text, marker_text, surface_id);
        }

        log_contract_event(
            "deferred-surface-row",
            &[
                ("surface_id", surface_id.to_string()),
                ("support_class", support_class.to_string()),
                ("owner_bead", owner_bead.to_string()),
                (
                    "doc_markers_checked",
                    array(row, "doc_markers").len().to_string(),
                ),
                ("verdict", "pass".to_string()),
                ("first_failure", String::new()),
            ],
        );
    }
}

#[test]
fn closed_reality_check_beads_record_exact_commits_evidence_files_and_commands() {
    let contract = contract();
    let rows = array(&contract, "closed_bead_evidence_checked");
    assert_eq!(
        rows.len(),
        9,
        "docs signoff should cover every closed technical reality-check bead"
    );

    for row in rows {
        let bead_id = nonempty_string(row, "bead_id");
        let commit = nonempty_string(row, "commit");
        assert!(
            is_full_hex_sha(commit),
            "{bead_id}: commit must be 40-char hex"
        );
        nonempty_string(row, "support_posture");

        let evidence_files = array(row, "evidence_files");
        assert!(
            !evidence_files.is_empty(),
            "{bead_id}: needs at least one evidence file"
        );
        for evidence_file in evidence_files {
            let path = evidence_file.as_str().expect("evidence file string");
            assert!(
                repo_path(path).exists(),
                "{bead_id}: evidence path must exist: {path}"
            );
        }

        let validation_commands = array(row, "validation_commands");
        assert!(
            !validation_commands.is_empty(),
            "{bead_id}: needs validation commands"
        );
        for command in validation_commands {
            let command = command.as_str().expect("validation command string");
            assert!(
                command.starts_with("rch exec -- ") || command == "bash scripts/scan_stubs.sh",
                "{bead_id}: validation command should be rch-backed or the dedicated docs/stub e2e script: {command}"
            );
            assert!(
                !command.contains("bash -lc"),
                "{bead_id}: validation command must not shell-wrap proof execution: {command}"
            );
        }
        if bead_id == "asupersync-rckfrm" {
            assert!(
                validation_commands
                    .iter()
                    .any(|command| command.as_str() == Some(DIRECT_FORMAL_LEAN_BUILD_COMMAND)),
                "{bead_id}: formal Lean proof command must use direct lake argv"
            );
        }

        log_contract_event(
            "closed-bead-evidence-row",
            &[
                ("closed_bead", bead_id.to_string()),
                ("commit", commit.to_string()),
                ("evidence_files", evidence_files.len().to_string()),
                ("validation_commands", validation_commands.len().to_string()),
                ("verdict", "pass".to_string()),
                ("first_failure", String::new()),
            ],
        );
    }
}

#[test]
fn e2e_docs_script_contract_logs_required_fields() {
    let contract = contract();
    let e2e = contract
        .get("e2e_logging_contract")
        .expect("e2e_logging_contract object");
    let script = nonempty_string(e2e, "script");
    let script_text = read_repo_file(script);
    assert_contains(&script_text, "asupersync-rckdoc", "e2e docs script");

    for field in array(e2e, "required_top_level_fields") {
        let field = field.as_str().expect("required field string");
        assert_contains(&script_text, field, "e2e docs script");
    }

    let artifact_path = nonempty_string(e2e, "default_artifact_path");
    assert!(
        artifact_path.ends_with("docs-evidence-report.json"),
        "default artifact should be a deterministic JSON report"
    );

    log_contract_event(
        "e2e-script-contract",
        &[
            ("script", script.to_string()),
            (
                "required_fields",
                array(e2e, "required_top_level_fields").len().to_string(),
            ),
            ("artifact_path", artifact_path.to_string()),
            ("verdict", "pass".to_string()),
            ("first_failure", String::new()),
        ],
    );
}
