#![allow(missing_docs)]

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use serde_json::Value;

fn repo_path(relative: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(relative)
}

fn read_repo_file(relative: &str) -> String {
    std::fs::read_to_string(repo_path(relative))
        .unwrap_or_else(|err| panic!("read {relative}: {err}"))
}

fn parse_module_after_marker(line: &str, marker: &str) -> Option<String> {
    let rest = line.trim_start().strip_prefix(marker)?.trim_start();
    let name = rest.strip_prefix("pub mod ")?;
    let module = name.split(';').next()?.trim();
    (!module.is_empty()).then(|| module.to_string())
}

fn live_registry_modules() -> (BTreeSet<String>, BTreeSet<String>) {
    let registry = read_repo_file("tests/conformance/mod.rs");
    let mut active = BTreeSet::new();
    let mut dormant = BTreeSet::new();

    for line in registry.lines() {
        if let Some(module) = parse_module_after_marker(line, "") {
            active.insert(module);
        } else if let Some(module) = parse_module_after_marker(line, "//") {
            dormant.insert(module);
        }
    }

    (active, dormant)
}

fn contract() -> Value {
    serde_json::from_str(&read_repo_file(
        "artifacts/conformance_registry_contract_v1.json",
    ))
    .expect("parse conformance registry contract")
}

fn string_set(value: &Value, key: &str) -> BTreeSet<String> {
    value
        .get(key)
        .and_then(Value::as_array)
        .unwrap_or_else(|| panic!("{key} must be an array"))
        .iter()
        .map(|item| {
            item.as_str()
                .unwrap_or_else(|| panic!("{key} entries must be strings"))
                .to_string()
        })
        .collect()
}

fn nonempty_string<'a>(value: &'a Value, key: &str) -> &'a str {
    let item = value
        .get(key)
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("{key} must be a string"));
    assert!(!item.trim().is_empty(), "{key} must be nonempty");
    item
}

#[test]
fn conformance_registry_contract_matches_live_mod_rs() {
    let contract = contract();
    assert_eq!(
        contract.get("contract_version").and_then(Value::as_str),
        Some("conformance-registry-contract-v1")
    );
    assert_eq!(
        contract.get("bead_id").and_then(Value::as_str),
        Some("asupersync-rckcnf")
    );
    assert_eq!(
        contract.get("source_registry").and_then(Value::as_str),
        Some("tests/conformance/mod.rs")
    );

    let (active, dormant) = live_registry_modules();
    assert_eq!(
        contract.get("active_module_count").and_then(Value::as_u64),
        Some(active.len() as u64)
    );
    assert_eq!(
        contract.get("dormant_module_count").and_then(Value::as_u64),
        Some(dormant.len() as u64)
    );
    assert_eq!(string_set(&contract, "active_modules"), active);

    let dormant_records = contract
        .get("dormant_modules")
        .and_then(Value::as_array)
        .expect("dormant_modules array");
    let contract_dormant: BTreeSet<_> = dormant_records
        .iter()
        .map(|record| nonempty_string(record, "module").to_string())
        .collect();
    assert_eq!(contract_dormant, dormant);

    for record in dormant_records {
        nonempty_string(record, "module");
        nonempty_string(record, "disposition");
        nonempty_string(record, "reason");
        nonempty_string(record, "retention_reason");
        assert!(
            record
                .get("line")
                .and_then(Value::as_u64)
                .is_some_and(|line| line > 0),
            "dormant module line must be a positive integer: {record:?}"
        );

        let has_owner_bead = record
            .get("owner_bead")
            .and_then(Value::as_str)
            .is_some_and(|value| value.starts_with("asupersync-"));
        let has_supersession = record
            .get("superseded_by")
            .and_then(Value::as_array)
            .is_some_and(|items| !items.is_empty() && items.iter().all(Value::is_string));
        let has_inline_followup = record
            .get("inline_followup")
            .and_then(Value::as_str)
            .is_some_and(|value| value.contains("tests/conformance/mod.rs"));
        assert!(
            has_owner_bead || has_supersession || has_inline_followup,
            "dormant module needs owner bead, supersession, or inline follow-up: {record:?}"
        );
    }
}

#[test]
fn readme_uses_checked_contract_instead_of_stale_counts() {
    let readme = read_repo_file("README.md");
    assert!(
        readme.contains("artifacts/conformance_registry_contract_v1.json"),
        "README should point to the checked registry contract"
    );
    assert!(
        readme.contains("tests/conformance_registry_contract.rs"),
        "README should name the doc truth test"
    );
    assert!(
        !readme.contains("61 `pub mod` suites"),
        "README must not preserve the stale active-suite count"
    );
    assert!(
        !readme.contains("currently leaves 21 `pub mod` entries"),
        "README must not preserve the stale dormant-suite count"
    );
}
