#![allow(missing_docs)]

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use conformance::{ReferenceRegistryError, ReferenceSurfaceRegistry, RuntimeConformanceVerdict};
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
fn reference_registry_api_rejects_unregistered_and_unwired_pass_claims() {
    let contract = contract();
    let api = contract.get("registry_api").expect("registry_api object");
    let source_path = nonempty_string(api, "source_path");
    assert_eq!(source_path, "conformance/src/reference_registry.rs");
    assert_eq!(
        nonempty_string(api, "crate_export"),
        "conformance::ReferenceSurfaceRegistry"
    );
    assert_eq!(
        nonempty_string(api, "admission_function"),
        "ReferenceSurfaceRegistry::admit_runtime_verdict"
    );

    let source = read_repo_file(source_path);
    for symbol in string_values(api, "required_symbols") {
        assert!(
            source.contains(symbol),
            "registry API source must contain required symbol {symbol:?}"
        );
    }
    let lib_source = read_repo_file("conformance/src/lib.rs");
    assert!(
        lib_source.contains("pub mod reference_registry;"),
        "conformance crate must expose the registry module"
    );
    assert!(
        lib_source.contains("ReferenceSurfaceRegistry"),
        "conformance crate must re-export ReferenceSurfaceRegistry"
    );

    let registry = ReferenceSurfaceRegistry::from_json_str(&read_repo_file(
        "artifacts/conformance_registry_contract_v1.json",
    ))
    .expect("load source-owned reference registry");
    assert_eq!(
        registry.len(),
        object_array(&contract, "reference_surfaces").len()
    );

    let logs_exporter = registry
        .surface("otel-logs-exporter")
        .expect("logs exporter reference surface row");
    assert_eq!(logs_exporter.binary, "otel_logs_exporter_conformance");
    assert!(!logs_exporter.has_live_reference());

    let pass_error = registry
        .admit_runtime_verdict("otel-logs-exporter", RuntimeConformanceVerdict::Pass)
        .expect_err("unwired reference must reject pass");
    assert!(matches!(
        pass_error,
        ReferenceRegistryError::UnwiredReferencePass { surface_id, .. }
            if surface_id == "otel-logs-exporter"
    ));
    registry
        .admit_runtime_verdict("otel-logs-exporter", RuntimeConformanceVerdict::Xfail)
        .expect("xfail is the admitted fail-closed verdict");

    let missing_error = registry
        .admit_runtime_verdict("missing-surface", RuntimeConformanceVerdict::Pass)
        .expect_err("missing registry rows must fail closed");
    assert_eq!(
        missing_error,
        ReferenceRegistryError::MissingSurfaceId("missing-surface".to_string())
    );

    for case in object_array(api, "fail_closed_cases") {
        let surface_id = nonempty_string(case, "surface_id");
        let candidate = match nonempty_string(case, "candidate_verdict") {
            "pass" => RuntimeConformanceVerdict::Pass,
            "fail" => RuntimeConformanceVerdict::Fail,
            "xfail" => RuntimeConformanceVerdict::Xfail,
            "unavailable" => RuntimeConformanceVerdict::Unavailable,
            other => panic!("unknown candidate verdict in registry_api case: {other}"),
        };
        let actual = registry
            .admit_runtime_verdict(surface_id, candidate)
            .expect_err("registry_api fail-closed case unexpectedly passed");
        let expected_error = nonempty_string(case, "expected_error");
        assert!(
            matches!(
                (&actual, expected_error),
                (
                    ReferenceRegistryError::MissingSurfaceId(_),
                    "MissingSurfaceId"
                ) | (
                    ReferenceRegistryError::UnwiredReferencePass { .. },
                    "UnwiredReferencePass"
                ) | (
                    ReferenceRegistryError::DisallowedVerdict { .. },
                    "DisallowedVerdict"
                )
            ),
            "registry_api case {} expected {expected_error}, got {actual:?}",
            nonempty_string(case, "case_id")
        );
    }

    log_contract_event(
        "registry-api-admission-guard",
        &[
            ("owner_bead", "asupersync-ghquqs".to_string()),
            ("source_path", source_path.to_string()),
            ("registered_surface_count", registry.len().to_string()),
            ("pass_guard", "unwired-reference-rejected".to_string()),
            ("missing_surface_guard", "fail-closed".to_string()),
            ("verdict", "pass".to_string()),
            ("first_failure", String::new()),
        ],
    );
}

#[test]
fn reference_registry_e2e_guard_walks_registered_bins() {
    let contract = contract();
    let api = contract.get("registry_api").expect("registry_api object");
    let guard = api.get("e2e_guard").expect("registry_api.e2e_guard object");
    let source_path = nonempty_string(guard, "source_path");
    let binary = nonempty_string(guard, "binary");
    let command = nonempty_string(guard, "command");

    assert_eq!(binary, "conformance_reference_registry_guard");
    assert_eq!(
        source_path,
        "conformance/src/bin/conformance_reference_registry_guard.rs"
    );
    assert!(
        command.starts_with("rch exec -- "),
        "guard command must route through rch: {command}"
    );
    assert!(
        command.contains("cargo run --manifest-path conformance/Cargo.toml --bin conformance_reference_registry_guard"),
        "guard command must run the guard binary: {command}"
    );
    assert!(
        repo_path(source_path).exists(),
        "guard source path must exist: {source_path}"
    );

    let cargo_toml = read_repo_file(nonempty_string(guard, "cargo_manifest"));
    assert!(cargo_toml.contains("name = \"conformance_reference_registry_guard\""));
    assert!(cargo_toml.contains("path = \"src/bin/conformance_reference_registry_guard.rs\""));

    let source = read_repo_file(source_path);
    for marker in [
        "ReferenceSurfaceRegistry::source_contract",
        "guard_report",
        "ExitCode::from(1)",
        "serde_json::to_string_pretty",
    ] {
        assert!(
            source.contains(marker),
            "guard source must contain marker {marker:?}"
        );
    }

    let registry = ReferenceSurfaceRegistry::from_json_str(&read_repo_file(
        "artifacts/conformance_registry_contract_v1.json",
    ))
    .expect("load source-owned reference registry");
    let report = registry.guard_report();
    assert!(report.is_pass(), "guard failures: {:?}", report.failures);
    assert_eq!(
        report.schema_version,
        nonempty_string(guard, "schema_version")
    );
    assert_eq!(
        report.checked_surface_count,
        object_array(&contract, "reference_surfaces").len()
    );

    let checked_binaries: BTreeSet<_> = report.checked_binaries.iter().cloned().collect();
    for surface in registry.surfaces() {
        assert!(
            checked_binaries.contains(&surface.binary),
            "guard report did not walk binary {}",
            surface.binary
        );
        assert!(
            surface
                .proof_command
                .contains(&format!("--bin {}", surface.binary)),
            "registered proof command must name its binary: {}",
            surface.proof_command
        );
    }

    for field in string_values(guard, "required_report_fields") {
        assert!(
            serde_json::to_value(&report)
                .expect("serialize guard report")
                .get(field)
                .is_some(),
            "guard report must serialize field {field}"
        );
    }

    let fail_closed = ReferenceSurfaceRegistry::from_json_str(
        r#"{
            "reference_surfaces": [
                {
                    "surface_id": "live-reference-without-proof",
                    "binary": "live_reference_without_proof_conformance",
                    "source_path": "conformance/src/bin/live_reference_without_proof_conformance.rs",
                    "reference_family": "demo",
                    "reference_status": "live_reference_wired",
                    "fail_closed_without_live_reference": false,
                    "runtime_allowed_verdicts": ["pass"],
                    "proof_command": "rch exec -- cargo test --manifest-path conformance/Cargo.toml --bin live_reference_without_proof_conformance",
                    "proof_lane": ""
                }
            ]
        }"#,
    )
    .expect("parse negative guard registry");
    let fail_report = fail_closed.guard_report();
    assert_eq!(fail_report.verdict, "fail_closed");
    assert!(fail_report.failures.iter().any(|failure| {
        failure.surface_id == "live-reference-without-proof"
            && failure.reason == "missing-proof-lane"
    }));
    assert!(
        string_values(guard, "fail_closed_reasons").contains(&"missing-proof-lane"),
        "contract must name the missing proof-lane fail-closed reason"
    );

    log_contract_event(
        "registry-e2e-guard",
        &[
            ("owner_bead", "asupersync-ghquqs".to_string()),
            ("binary", binary.to_string()),
            (
                "checked_surface_count",
                report.checked_surface_count.to_string(),
            ),
            ("schema_version", report.schema_version.to_string()),
            (
                "fail_closed_negative_case",
                "missing-proof-lane".to_string(),
            ),
            ("verdict", "pass".to_string()),
            ("first_failure", String::new()),
        ],
    );
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
