//! Fail-closed contract for the dormant real-E2E inventory.
//!
//! Bead: asupersync-d24mms.12.1
//! Fixture: artifacts/dormant_e2e_inventory_v1.json

#![allow(missing_docs)]

use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

const ARTIFACT_PATH: &str = "artifacts/dormant_e2e_inventory_v1.json";
const DOC_PATH: &str = "docs/dormant_e2e_inventory.md";
const LIB_PATH: &str = "src/lib.rs";
const BEAD_ID: &str = "asupersync-d24mms.12.1";
const CAPABILITY_IDS: [&str; 2] = ["CAP-REAL-SERVICE-E2E", "CAP-VERIFICATION-PROFILES"];
const FORBIDDEN_MODULE_DECLARATIONS: [&str; 3] = [
    "mod real_fs_dir_fs_vfs_integration_e2e_tests;",
    "mod real_integration_scenarios_e2e_tests;",
    "mod real_distributed_e2e_tests;",
];

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn read_repo_file(path: &str) -> String {
    std::fs::read_to_string(repo_root().join(path))
        .unwrap_or_else(|error| panic!("failed to read {path}: {error}"))
}

fn parse_inventory() -> Value {
    serde_json::from_str(&read_repo_file(ARTIFACT_PATH))
        .unwrap_or_else(|error| panic!("{ARTIFACT_PATH} must be valid JSON: {error}"))
}

fn array<'a>(value: &'a Value, key: &str) -> &'a [Value] {
    value
        .get(key)
        .and_then(Value::as_array)
        .unwrap_or_else(|| panic!("{key} must be an array"))
}

fn string<'a>(value: &'a Value, key: &str) -> &'a str {
    value
        .get(key)
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("{key} must be a string"))
}

fn strings(value: &Value, key: &str) -> Vec<String> {
    array(value, key)
        .iter()
        .map(|entry| {
            entry
                .as_str()
                .unwrap_or_else(|| panic!("{key} entries must be strings"))
                .to_owned()
        })
        .collect()
}

fn sha256(path: &str) -> String {
    let bytes = std::fs::read(repo_root().join(path))
        .unwrap_or_else(|error| panic!("failed to read {path}: {error}"));
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn assert_nonempty_strings(row: &Value, key: &str, context: &str) {
    let values = array(row, key);
    assert!(!values.is_empty(), "{context}: {key} must not be empty");
    assert!(
        values
            .iter()
            .all(|value| value.as_str().is_some_and(|text| !text.trim().is_empty())),
        "{context}: {key} entries must be nonempty strings"
    );
}

fn assert_nonempty_string(row: &Value, key: &str, context: &str) {
    assert!(
        row.get(key)
            .and_then(Value::as_str)
            .is_some_and(|text| !text.trim().is_empty()),
        "{context}: {key} must be a nonempty string"
    );
}

fn structural_errors(inventory: &Value) -> Vec<String> {
    let mut errors = Vec::new();
    let Some(rows) = inventory.get("test_inventory").and_then(Value::as_array) else {
        return vec!["test_inventory is missing".to_owned()];
    };
    if rows.len() != 27 {
        errors.push(format!("expected 27 inventory rows, found {}", rows.len()));
    }
    for (index, row) in rows.iter().enumerate() {
        if row
            .get("repair_owner")
            .and_then(Value::as_str)
            .is_none_or(str::is_empty)
        {
            errors.push(format!("row {index} has no repair owner"));
        }
    }
    let Some(modules) = inventory.get("modules").and_then(Value::as_array) else {
        errors.push("modules is missing".to_owned());
        return errors;
    };
    for (index, module) in modules.iter().enumerate() {
        if module
            .pointer("/compile_probe/outcome")
            .and_then(Value::as_str)
            != Some("BLOCKED_COMPILE_DRIFT")
        {
            errors.push(format!("module {index} is not fail-closed"));
        }
    }
    errors
}

#[test]
fn inventory_pins_all_dormant_sources_and_compile_drift() {
    let inventory = parse_inventory();
    assert_eq!(structural_errors(&inventory), Vec::<String>::new());
    assert_eq!(string(&inventory, "bead_id"), BEAD_ID);
    assert_eq!(
        strings(&inventory, "capability_ids"),
        CAPABILITY_IDS.map(str::to_owned)
    );

    let modules = array(&inventory, "modules");
    assert_eq!(modules.len(), 3);
    let expected = BTreeMap::from([
        (
            "src/real_fs_dir_fs_vfs_integration_e2e_tests.rs",
            (
                "ffda7940ab83b3c7abbf41e8b9734759a35ebb315f36807d779e5163db4c9266",
                1223_u64,
                5_u64,
                8_u64,
                BTreeSet::from(["E0432", "E0599", "E0603"]),
            ),
        ),
        (
            "src/real_integration_scenarios_e2e_tests.rs",
            (
                "2caab9f01c37d1dff1698aec59b1aea4fce40db86ffa3094d231206cd7cb97de",
                5728,
                17,
                247,
                BTreeSet::from([
                    "E0061", "E0277", "E0308", "E0423", "E0425", "E0432", "E0532", "E0599", "E0608",
                ]),
            ),
        ),
        (
            "src/real_distributed_e2e_tests.rs",
            (
                "315a2c5ff591437348b3ec7f49c2b88de5bc3e6cefff1d3fdfc6d4c1aed243ae",
                828,
                5,
                23,
                BTreeSet::from(["E0061", "E0277", "E0599"]),
            ),
        ),
    ]);

    for module in modules {
        let path = string(module, "path");
        let &(hash, line_count, entrypoint_count, error_count, ref error_codes) = expected
            .get(path)
            .unwrap_or_else(|| panic!("unexpected module {path}"));
        assert_eq!(string(module, "sha256"), hash, "{path}: stale hash pin");
        assert_eq!(sha256(path), hash, "{path}: source changed after inventory");
        assert_eq!(
            std::fs::read_to_string(repo_root().join(path))
                .expect("inventoried source must be readable")
                .lines()
                .count() as u64,
            line_count,
            "{path}: stale line count"
        );
        assert_eq!(
            module.get("line_count").and_then(Value::as_u64),
            Some(line_count)
        );
        assert_eq!(
            module.get("entrypoint_count").and_then(Value::as_u64),
            Some(entrypoint_count)
        );
        assert_eq!(module.get("declared_in_lib"), Some(&Value::Bool(false)));
        assert_nonempty_strings(module, "logical_scenarios", path);
        assert_nonempty_strings(module, "fixtures", path);
        assert_nonempty_string(module, "cleanup_contract", path);

        let probe = module
            .get("compile_probe")
            .expect("compile_probe must be present");
        assert_eq!(string(probe, "outcome"), "BLOCKED_COMPILE_DRIFT");
        assert_eq!(probe.get("exit_code").and_then(Value::as_i64), Some(101));
        assert_eq!(
            probe.get("error_count").and_then(Value::as_u64),
            Some(error_count)
        );
        assert_eq!(
            strings(probe, "error_codes")
                .into_iter()
                .collect::<BTreeSet<_>>(),
            error_codes
                .iter()
                .map(|code| (*code).to_owned())
                .collect::<BTreeSet<_>>()
        );
        assert!(
            string(probe, "command").contains("RCH_REQUIRE_REMOTE=1 rch exec"),
            "{path}: compile probe must be remote-required"
        );
        assert_nonempty_strings(probe, "representative_diagnostics", path);
    }
}

#[test]
fn every_test_entrypoint_has_fail_closed_ownership_and_evidence() {
    let inventory = parse_inventory();
    let rows = array(&inventory, "test_inventory");
    assert_eq!(rows.len(), 27);

    let expected_counts = BTreeMap::from([
        (
            "src/real_fs_dir_fs_vfs_integration_e2e_tests.rs",
            (5_usize, "#[test]", "asupersync-d24mms.12.2"),
        ),
        (
            "src/real_integration_scenarios_e2e_tests.rs",
            (17, "#[tokio::test]", "asupersync-d24mms.12.3"),
        ),
        (
            "src/real_distributed_e2e_tests.rs",
            (5, "#[test]", "asupersync-d24mms.12.4"),
        ),
    ]);

    let mut ids = BTreeSet::new();
    let mut names_by_file: BTreeMap<&str, BTreeSet<&str>> = BTreeMap::new();
    let mut blocked = 0;
    let mut placeholders = 0;

    for row in rows {
        let id = string(row, "scenario_id");
        assert!(ids.insert(id), "duplicate scenario_id {id}");
        let source = string(row, "source_file");
        let test_function = string(row, "test_function");
        let &(_, _, owner) = expected_counts
            .get(source)
            .unwrap_or_else(|| panic!("{id}: unexpected source_file {source}"));
        assert_eq!(string(row, "repair_owner"), owner, "{id}: wrong owner");
        assert!(
            read_repo_file(source).contains(&format!("fn {test_function}")),
            "{id}: {test_function} is not present in {source}"
        );
        assert!(
            names_by_file
                .entry(source)
                .or_default()
                .insert(test_function),
            "{id}: duplicate test function inventory"
        );
        assert_nonempty_strings(row, "covers", id);
        assert_nonempty_strings(row, "expected_assertions", id);
        assert_nonempty_strings(row, "fixtures", id);
        assert_nonempty_strings(row, "cleanup", id);
        match string(row, "status") {
            "BLOCKED_REPAIR" => blocked += 1,
            "PLACEHOLDER_NOT_EVIDENCE" => {
                placeholders += 1;
                assert_eq!(string(row, "coverage"), "NO_COVERAGE");
                assert!(
                    array(row, "existing_evidence").is_empty(),
                    "{id}: placeholder cannot cite replacement evidence"
                );
            }
            status => panic!("{id}: non-fail-closed status {status}"),
        }
    }

    assert_eq!(blocked, 26);
    assert_eq!(placeholders, 1);
    for (source, (count, attribute, _)) in expected_counts {
        assert_eq!(
            names_by_file.get(source).map(BTreeSet::len),
            Some(count),
            "{source}: incomplete inventory"
        );
        assert_eq!(
            read_repo_file(source).matches(attribute).count(),
            count,
            "{source}: test attribute count drifted"
        );
    }
}

#[test]
fn dormant_state_policy_and_human_matrix_are_discoverable() {
    let inventory = parse_inventory();
    let lib = read_repo_file(LIB_PATH);
    for declaration in FORBIDDEN_MODULE_DECLARATIONS {
        assert!(
            !lib.contains(declaration),
            "{declaration} became active without downstream repair proof"
        );
    }

    let requirements = inventory
        .get("common_test_requirements")
        .expect("common_test_requirements must be present");
    assert_eq!(
        strings(requirements, "capability_ids"),
        CAPABILITY_IDS.map(str::to_owned)
    );
    assert_eq!(
        string(requirements, "runner_owner"),
        "asupersync-d24mms.12.5"
    );
    for invariant in [
        "no task leaks",
        "no obligation leaks",
        "race losers drained",
        "region close implies quiescence",
    ] {
        assert!(
            strings(requirements, "required_invariants")
                .iter()
                .any(|entry| entry == invariant),
            "missing invariant {invariant}"
        );
    }

    let summary = inventory.get("summary").expect("summary must be present");
    assert_eq!(
        summary.get("entrypoint_count").and_then(Value::as_u64),
        Some(27)
    );
    assert_eq!(
        summary
            .get("compiled_entrypoint_count")
            .and_then(Value::as_u64),
        Some(0)
    );
    assert_eq!(
        summary
            .get("deleted_or_ignored_count")
            .and_then(Value::as_u64),
        Some(0)
    );
    assert_eq!(
        summary.get("compile_error_count").and_then(Value::as_u64),
        Some(278)
    );
    assert_nonempty_strings(&inventory, "no_claim_boundaries", "inventory");

    let docs = read_repo_file(DOC_PATH);
    for marker in [
        "None of their tests currently",
        "Twenty-six",
        "`PLACEHOLDER_NOT_EVIDENCE`",
        "No dormant journey is",
        "no task leaks",
        "region-close quiescence",
    ] {
        assert!(docs.contains(marker), "docs missing marker {marker}");
    }
}

#[test]
fn malformed_inventory_fails_closed() {
    let inventory = parse_inventory();

    let mut missing_row = inventory.clone();
    missing_row
        .get_mut("test_inventory")
        .and_then(Value::as_array_mut)
        .expect("test_inventory must be mutable")
        .pop();
    assert!(
        structural_errors(&missing_row)
            .iter()
            .any(|error| error.contains("expected 27 inventory rows"))
    );

    let mut false_green = inventory.clone();
    false_green["modules"][0]["compile_probe"]["outcome"] = Value::String("COMPILED".into());
    assert!(
        structural_errors(&false_green)
            .iter()
            .any(|error| error.contains("not fail-closed"))
    );

    let mut missing_owner = inventory.clone();
    missing_owner["test_inventory"][0]["repair_owner"] = Value::String(String::new());
    assert!(
        structural_errors(&missing_owner)
            .iter()
            .any(|error| error.contains("no repair owner"))
    );
}
