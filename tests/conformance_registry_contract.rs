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

fn registry_modules_from_str(registry: &str) -> (BTreeSet<String>, BTreeSet<String>) {
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

fn live_registry_modules() -> (BTreeSet<String>, BTreeSet<String>) {
    let registry = read_repo_file("tests/conformance/mod.rs");
    registry_modules_from_str(&registry)
}

fn contract() -> Value {
    serde_json::from_str(&read_repo_file(
        "artifacts/conformance_registry_contract_v1.json",
    ))
    .expect("parse conformance registry contract")
}

fn object_array<'a>(value: &'a Value, key: &str) -> &'a [Value] {
    let items = value
        .get(key)
        .and_then(Value::as_array)
        .unwrap_or_else(|| panic!("{key} must be an array"));
    assert!(
        items.iter().all(Value::is_object),
        "{key} entries must be objects"
    );
    items
}

fn string_values<'a>(value: &'a Value, key: &str) -> Vec<&'a str> {
    value
        .get(key)
        .and_then(Value::as_array)
        .unwrap_or_else(|| panic!("{key} must be an array"))
        .iter()
        .map(|item| {
            let value = item
                .as_str()
                .unwrap_or_else(|| panic!("{key} entries must be strings"));
            assert!(!value.trim().is_empty(), "{key} entries must be nonempty");
            value
        })
        .collect()
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

fn log_contract_event(scenario_id: &str, fields: &[(&str, String)]) {
    let mut parts = vec![
        "bead_id=asupersync-rckcnf".to_string(),
        format!("scenario_id={scenario_id}"),
    ];
    parts.extend(fields.iter().map(|(key, value)| format!("{key}={value}")));
    println!("{}", parts.join(" "));
}

#[test]
fn registry_parser_handles_active_dormant_blank_and_duplicate_rows() {
    let fixture = r"
        pub mod active_one;
        pub mod active_one;
        // pub mod dormant_one;
        //   pub mod dormant_two;
        // not a module
        pub mod active_two; // trailing note
        pub(crate) mod private_module;
        // pub crate::not_module;
    ";

    let (active, dormant) = registry_modules_from_str(fixture);
    assert_eq!(
        active,
        BTreeSet::from(["active_one".to_string(), "active_two".to_string()])
    );
    assert_eq!(
        dormant,
        BTreeSet::from(["dormant_one".to_string(), "dormant_two".to_string()])
    );

    log_contract_event(
        "registry-parser-unit",
        &[
            ("registry_path", "fixture:inline".to_string()),
            ("active_count", active.len().to_string()),
            ("dormant_count", dormant.len().to_string()),
            ("docs_checked", "none".to_string()),
            ("verdict", "pass".to_string()),
            ("first_failure", String::new()),
        ],
    );
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
        let module = nonempty_string(record, "module");
        let disposition = nonempty_string(record, "disposition");
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
        log_contract_event(
            "registry-dormant-disposition",
            &[
                ("registry_path", "tests/conformance/mod.rs".to_string()),
                ("module", module.to_string()),
                ("disposition", disposition.to_string()),
                (
                    "owner_bead",
                    record
                        .get("owner_bead")
                        .and_then(Value::as_str)
                        .unwrap_or("")
                        .to_string(),
                ),
                (
                    "superseded_by_count",
                    record
                        .get("superseded_by")
                        .and_then(Value::as_array)
                        .map_or(0, Vec::len)
                        .to_string(),
                ),
                ("verdict", "pass".to_string()),
                ("first_failure", String::new()),
            ],
        );
    }

    log_contract_event(
        "registry-contract-live",
        &[
            ("registry_path", "tests/conformance/mod.rs".to_string()),
            ("active_count", active.len().to_string()),
            ("dormant_count", dormant.len().to_string()),
            (
                "artifact_path",
                "artifacts/conformance_registry_contract_v1.json".to_string(),
            ),
            ("docs_checked", "README.md".to_string()),
            ("verdict", "pass".to_string()),
            ("first_failure", String::new()),
        ],
    );
}

#[test]
fn reference_surface_registry_rejects_unwired_live_reference_claims() {
    let contract = contract();
    let policy = contract
        .get("reference_surface_policy")
        .expect("reference_surface_policy object");
    assert_eq!(
        nonempty_string(policy, "owner_bead"),
        "asupersync-ghquqs",
        "reference surface policy must name the owning bead"
    );
    assert!(
        string_values(policy, "required_for_unwired_reference")
            .iter()
            .any(|requirement| requirement.contains("fail_closed_without_live_reference")),
        "policy must require fail-closed behavior for unwired references"
    );

    let surfaces = object_array(&contract, "reference_surfaces");
    assert!(
        !surfaces.is_empty(),
        "reference_surfaces must record every hardened conformance reference"
    );

    let mut surface_ids = BTreeSet::new();
    for surface in surfaces {
        let surface_id = nonempty_string(surface, "surface_id");
        assert!(
            surface_ids.insert(surface_id.to_string()),
            "duplicate reference surface id: {surface_id}"
        );

        let binary = nonempty_string(surface, "binary");
        let source_path = nonempty_string(surface, "source_path");
        assert!(
            repo_path(source_path).exists(),
            "reference surface source path does not exist: {source_path}"
        );
        let source = read_repo_file(source_path);

        let proof_command = nonempty_string(surface, "proof_command");
        assert!(
            proof_command.starts_with("rch exec -- "),
            "proof command must use rch: {proof_command}"
        );
        assert!(
            proof_command.contains("cargo test"),
            "proof command must run a cargo test lane: {proof_command}"
        );
        assert!(
            proof_command.contains(binary),
            "proof command must name the conformance binary {binary}: {proof_command}"
        );
        nonempty_string(surface, "proof_lane");

        let reference_status = nonempty_string(surface, "reference_status");
        let allowed_verdicts = string_set(surface, "runtime_allowed_verdicts");
        assert!(
            !allowed_verdicts.is_empty(),
            "runtime_allowed_verdicts must be nonempty for {surface_id}"
        );
        if reference_status != "live_reference_wired" {
            assert_eq!(
                surface
                    .get("fail_closed_without_live_reference")
                    .and_then(Value::as_bool),
                Some(true),
                "unwired reference must fail closed: {surface_id}"
            );
            assert!(
                !allowed_verdicts.contains("pass"),
                "unwired reference must not allow pass verdicts: {surface_id}"
            );
            assert!(
                allowed_verdicts
                    .iter()
                    .all(|verdict| matches!(verdict.as_str(), "xfail" | "fail" | "unavailable")),
                "unwired reference allowed unexpected runtime verdicts for {surface_id}: {allowed_verdicts:?}"
            );
            assert!(
                source.contains("XFAIL")
                    || source.contains("REFERENCE UNAVAILABLE")
                    || source.contains("reference unavailable"),
                "unwired reference source must expose an XFAIL or unavailable marker: {surface_id}"
            );
        }

        for marker in string_values(surface, "required_source_markers") {
            assert!(
                source.contains(marker),
                "source {source_path} for {surface_id} must contain marker {marker:?}"
            );
        }
        for token in string_values(surface, "forbidden_source_tokens") {
            assert!(
                !source.contains(token),
                "source {source_path} for {surface_id} still contains stale token {token:?}"
            );
        }

        log_contract_event(
            "registry-reference-surface",
            &[
                ("owner_bead", "asupersync-ghquqs".to_string()),
                ("surface_id", surface_id.to_string()),
                ("source_path", source_path.to_string()),
                ("reference_status", reference_status.to_string()),
                (
                    "proof_lane",
                    nonempty_string(surface, "proof_lane").to_string(),
                ),
                ("verdict", "pass".to_string()),
                ("first_failure", String::new()),
            ],
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
    log_contract_event(
        "readme-doc-truth",
        &[
            ("registry_path", "tests/conformance/mod.rs".to_string()),
            ("active_count", "checked-by-contract".to_string()),
            ("dormant_count", "checked-by-contract".to_string()),
            ("docs_checked", "README.md".to_string()),
            (
                "artifact_path",
                "artifacts/conformance_registry_contract_v1.json".to_string(),
            ),
            ("verdict", "pass".to_string()),
            ("first_failure", String::new()),
        ],
    );
}
