#![allow(clippy::nursery, clippy::pedantic, missing_docs)]

use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

const ARTIFACT_PATH: &str = "artifacts/dependency_feature_platform_consumer_matrix_v1.json";
const REGISTRY_PATH: &str = "artifacts/dependency_capability_registry_v1.json";
const SERVICE_MATRIX_PATH: &str = "artifacts/dependency_real_service_fixture_matrix_v1.json";
const DOCS_PATH: &str = "docs/dependency_feature_platform_consumer_matrix.md";
const RUNNER_PATH: &str = "scripts/run_dependency_sovereignty_e2e.sh";
const BEAD_ID: &str = "asupersync-dep-p1-foundations-upksjk.6.5";

fn repo_path(relative: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(relative)
}

fn read_repo_file(relative: &str) -> String {
    std::fs::read_to_string(repo_path(relative))
        .unwrap_or_else(|err| panic!("read {relative}: {err}"))
}

fn json(relative: &str) -> Value {
    serde_json::from_str(&read_repo_file(relative))
        .unwrap_or_else(|err| panic!("parse {relative}: {err}"))
}

fn array<'a>(value: &'a Value, key: &str) -> &'a [Value] {
    value
        .get(key)
        .and_then(Value::as_array)
        .map_or_else(|| panic!("{key} must be an array"), Vec::as_slice)
}

fn string<'a>(value: &'a Value, key: &str) -> &'a str {
    let text = value
        .get(key)
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("{key} must be a string"));
    assert!(!text.trim().is_empty(), "{key} must be nonempty");
    text
}

fn optional_string<'a>(value: &'a Value, key: &str) -> Option<&'a str> {
    value.get(key).and_then(Value::as_str)
}

fn bool_field(value: &Value, key: &str) -> bool {
    value
        .get(key)
        .and_then(Value::as_bool)
        .unwrap_or_else(|| panic!("{key} must be a bool"))
}

fn string_set(value: &Value, key: &str) -> BTreeSet<String> {
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

fn cargo_feature_names() -> BTreeSet<String> {
    let manifest = read_repo_file("Cargo.toml");
    let mut in_features = false;
    let mut features = BTreeSet::new();
    for line in manifest.lines() {
        let trimmed = line.trim();
        if trimmed == "[features]" {
            in_features = true;
            continue;
        }
        if in_features && trimmed.starts_with('[') {
            break;
        }
        if !in_features
            || trimmed.is_empty()
            || trimmed.starts_with('#')
            || line.chars().next().is_some_and(char::is_whitespace)
        {
            continue;
        }
        if let Some((name, _)) = trimmed.split_once('=') {
            let feature = name.trim();
            if !feature.is_empty() {
                features.insert(feature.to_owned());
            }
        }
    }
    features
}

fn registry_feature_names(registry: &Value) -> BTreeSet<String> {
    array(registry, "feature_inventory")
        .iter()
        .map(|entry| string(entry, "feature_id").to_owned())
        .collect()
}

fn registry_capability_names(registry: &Value) -> BTreeSet<String> {
    array(registry, "capabilities")
        .iter()
        .map(|entry| string(entry, "capability_id").to_owned())
        .collect()
}

fn registry_platform_selectors(registry: &Value) -> BTreeSet<String> {
    let mut selectors = BTreeSet::new();
    for feature in array(registry, "feature_inventory") {
        selectors.extend(string_set(feature, "platforms"));
    }
    for capability in array(registry, "capabilities") {
        selectors.extend(string_set(capability, "platforms"));
    }
    selectors
}

fn named_rows<'a>(value: &'a Value, array_key: &str, id_key: &str) -> BTreeMap<String, &'a Value> {
    array(value, array_key)
        .iter()
        .map(|row| (string(row, id_key).to_owned(), row))
        .collect()
}

fn is_remote_command(command: &str) -> bool {
    command.starts_with("RCH_REQUIRE_REMOTE=1 rch exec ")
        || command.starts_with("RCH_REQUIRE_REMOTE=1 bash scripts/run_stable_lane_e2e.sh")
}

fn push_error(errors: &mut Vec<String>, condition: bool, message: impl Into<String>) {
    if !condition {
        errors.push(message.into());
    }
}

fn validate_matrix(
    matrix: &Value,
    registry: &Value,
    service_matrix: &Value,
    cargo_features: &BTreeSet<String>,
) -> Vec<String> {
    let mut errors = Vec::new();
    let allowed_outcomes = string_set(matrix, "allowed_outcomes");
    let capabilities = registry_capability_names(registry);
    let registry_features = registry_feature_names(registry);

    push_error(
        &mut errors,
        matrix.get("schema_version").and_then(Value::as_str)
            == Some("dependency-feature-platform-consumer-matrix-v1"),
        "schema version mismatch",
    );
    push_error(
        &mut errors,
        matrix.get("bead_id").and_then(Value::as_str) == Some(BEAD_ID),
        "bead ID mismatch",
    );
    push_error(
        &mut errors,
        cargo_features == &registry_features,
        "Cargo and registry feature inventories differ",
    );

    let profiles = named_rows(matrix, "sparse_feature_profiles", "feature_id");
    push_error(
        &mut errors,
        profiles.len() == cargo_features.len(),
        format!(
            "sparse profile count {} must equal Cargo feature count {}",
            profiles.len(),
            cargo_features.len()
        ),
    );
    for feature in cargo_features {
        let Some(profile) = profiles.get(feature) else {
            errors.push(format!("missing sparse feature profile {feature}"));
            continue;
        };
        let context = format!("sparse profile {feature}");
        push_error(
            &mut errors,
            string(profile, "outcome") == "RERUN_REQUIRED",
            format!("{context} must remain RERUN_REQUIRED"),
        );
        push_error(
            &mut errors,
            allowed_outcomes.contains(string(profile, "outcome")),
            format!("{context} has unknown outcome"),
        );
        if feature == "default" {
            push_error(
                &mut errors,
                bool_field(profile, "default_features"),
                "default profile must enable default features",
            );
            push_error(
                &mut errors,
                array(profile, "requested_features").is_empty(),
                "default profile must not spell a direct --features selector",
            );
            push_error(
                &mut errors,
                string(profile, "command_template_id") == "nightly-default-lib-check",
                "default profile must use the default command template",
            );
        } else {
            push_error(
                &mut errors,
                !bool_field(profile, "default_features"),
                format!("{context} must disable default features"),
            );
            push_error(
                &mut errors,
                array(profile, "requested_features") == [Value::String(feature.clone())].as_slice(),
                format!("{context} must select exactly one direct feature"),
            );
            push_error(
                &mut errors,
                string(profile, "command_template_id") == "nightly-sparse-lib-check",
                format!("{context} must use the sparse command template"),
            );
        }
    }
    for profile_feature in profiles.keys() {
        push_error(
            &mut errors,
            cargo_features.contains(profile_feature),
            format!("unknown sparse feature profile {profile_feature}"),
        );
    }

    let templates = named_rows(matrix, "command_templates", "template_id");
    for required in ["nightly-default-lib-check", "nightly-sparse-lib-check"] {
        push_error(
            &mut errors,
            templates.contains_key(required),
            format!("missing command template {required}"),
        );
    }
    for (template_id, template) in templates {
        let command = optional_string(template, "command")
            .or_else(|| optional_string(template, "command_template"))
            .unwrap_or("");
        push_error(
            &mut errors,
            is_remote_command(command),
            format!("{template_id} must require remote RCH"),
        );
        push_error(
            &mut errors,
            template.get("no_local_fallback").and_then(Value::as_bool) == Some(true),
            format!("{template_id} must refuse local fallback"),
        );
    }

    let target_rows = named_rows(matrix, "target_catalog", "target_id");
    let target_ids = target_rows.keys().cloned().collect::<BTreeSet<_>>();
    let host_rows = named_rows(matrix, "host_catalog", "host_id");
    let host_ids = host_rows.keys().cloned().collect::<BTreeSet<_>>();
    push_error(
        &mut errors,
        target_ids.is_disjoint(&host_ids),
        "host IDs and target IDs must be disjoint namespaces",
    );
    for (target_id, target) in &target_rows {
        let host_id = string(target, "host_id");
        push_error(
            &mut errors,
            host_ids.contains(host_id),
            format!("{target_id} references unknown host {host_id}"),
        );
        push_error(
            &mut errors,
            !string(target, "target_triple").is_empty(),
            format!("{target_id} target triple is empty"),
        );
        for (outcome_key, command_key) in [
            ("compile_outcome", "compile_command"),
            ("runtime_outcome", "runtime_command"),
        ] {
            let outcome = string(target, outcome_key);
            push_error(
                &mut errors,
                allowed_outcomes.contains(outcome),
                format!("{target_id}/{outcome_key} uses forbidden outcome {outcome}"),
            );
            if outcome == "RERUN_REQUIRED" {
                push_error(
                    &mut errors,
                    optional_string(target, command_key).is_some_and(is_remote_command),
                    format!("{target_id}/{outcome_key} needs an exact remote command"),
                );
            } else {
                push_error(
                    &mut errors,
                    optional_string(target, "blocker").is_some_and(|text| !text.trim().is_empty()),
                    format!("{target_id}/{outcome_key} needs a blocker or no-claim rationale"),
                );
            }
        }
    }

    let selector_rows = named_rows(matrix, "platform_selector_expansions", "selector");
    let actual_selectors = selector_rows.keys().cloned().collect::<BTreeSet<_>>();
    let required_selectors = registry_platform_selectors(registry);
    push_error(
        &mut errors,
        actual_selectors == required_selectors,
        format!(
            "platform selectors differ: actual={actual_selectors:?} required={required_selectors:?}"
        ),
    );
    for (selector, row) in &selector_rows {
        let expanded_targets = string_set(row, "target_ids");
        push_error(
            &mut errors,
            !expanded_targets.is_empty(),
            format!("platform selector {selector} has no targets"),
        );
        for target_id in expanded_targets {
            push_error(
                &mut errors,
                target_ids.contains(&target_id),
                format!("platform selector {selector} references unknown target {target_id}"),
            );
        }
    }

    for feature in array(registry, "feature_inventory") {
        let feature_id = string(feature, "feature_id");
        for capability_id in string_set(feature, "capability_ids") {
            push_error(
                &mut errors,
                capabilities.contains(&capability_id),
                format!("{feature_id} maps unknown capability {capability_id}"),
            );
        }
        for selector in string_set(feature, "platforms") {
            push_error(
                &mut errors,
                selector_rows.contains_key(&selector),
                format!("{feature_id} maps unknown platform selector {selector}"),
            );
        }
    }
    for capability in array(registry, "capabilities") {
        let capability_id = string(capability, "capability_id");
        for feature_id in string_set(capability, "features") {
            push_error(
                &mut errors,
                profiles.contains_key(&feature_id),
                format!("{capability_id} lacks feature profile {feature_id}"),
            );
        }
        for selector in string_set(capability, "platforms") {
            push_error(
                &mut errors,
                selector_rows.contains_key(&selector),
                format!("{capability_id} lacks platform selector {selector}"),
            );
        }
    }

    let combinations = named_rows(matrix, "combination_profiles", "profile_id");
    let required_combinations = BTreeSet::from([
        "stable-no-default-proc-macros",
        "nightly-default-all-targets",
        "nightly-test-internals-all-targets",
        "metrics-tracing",
        "tls-native-roots",
        "tls-webpki-roots",
        "quic-http3-tls",
        "sqlite-test-internals",
        "kafka-test-internals",
        "wasm-browser-prod-target",
        "wasm-browser-deterministic-target",
        "fuzz-quarantine",
        "workspace-cross-platform-quarantine",
    ]);
    push_error(
        &mut errors,
        combinations
            .keys()
            .map(String::as_str)
            .collect::<BTreeSet<_>>()
            == required_combinations,
        "combination profile catalog differs",
    );
    for (profile_id, profile) in &combinations {
        for feature in string_set(profile, "requested_features") {
            push_error(
                &mut errors,
                cargo_features.contains(&feature),
                format!("{profile_id} references unknown feature {feature}"),
            );
        }
        push_error(
            &mut errors,
            target_ids.contains(string(profile, "target_id")),
            format!("{profile_id} references unknown target"),
        );
        push_error(
            &mut errors,
            is_remote_command(string(profile, "command")),
            format!("{profile_id} must have an exact remote command"),
        );
        push_error(
            &mut errors,
            string(profile, "outcome") == "RERUN_REQUIRED",
            format!("{profile_id} must remain RERUN_REQUIRED"),
        );
    }
    if let Some(stable) = combinations.get("stable-no-default-proc-macros") {
        push_error(
            &mut errors,
            string_set(stable, "requested_features") == BTreeSet::from(["proc-macros".to_owned()]),
            "stable lane must select only proc-macros",
        );
        push_error(
            &mut errors,
            string(stable, "command") == "RCH_REQUIRE_REMOTE=1 bash scripts/run_stable_lane_e2e.sh",
            "stable lane must use the canonical stable script",
        );
    }

    let consumers = named_rows(
        matrix,
        "maintained_consumer_profiles",
        "consumer_profile_id",
    );
    let required_consumers = BTreeSet::from([
        "generic-serde-protobuf-consumer",
        "downstream-stream-trait-consumer",
        "cli-config-workflow-consumer",
        "metrics-exporter-consumer",
        "tower-adapter-consumer",
        "http-compression-public-consumer",
        "sqlite-real-file-adapter",
        "nkey-protocol-boundary",
        "kafka-real-service-boundary",
        "tls-external-peer-boundary",
        "external-portfolio-runtime",
    ]);
    push_error(
        &mut errors,
        consumers
            .keys()
            .map(String::as_str)
            .collect::<BTreeSet<_>>()
            == required_consumers,
        "maintained consumer catalog differs",
    );
    for (consumer_id, consumer) in &consumers {
        for capability_id in string_set(consumer, "capability_ids") {
            push_error(
                &mut errors,
                capabilities.contains(&capability_id),
                format!("{consumer_id} references unknown capability {capability_id}"),
            );
        }
        for fixture in array(consumer, "fixture_paths") {
            let fixture = fixture.as_str().expect("fixture path string");
            push_error(
                &mut errors,
                repo_path(fixture).exists(),
                format!("{consumer_id} fixture does not exist: {fixture}"),
            );
        }
        push_error(
            &mut errors,
            target_ids.contains(string(consumer, "target_id")),
            format!("{consumer_id} references unknown target"),
        );
        let outcome = string(consumer, "outcome");
        push_error(
            &mut errors,
            allowed_outcomes.contains(outcome),
            format!("{consumer_id} uses unknown outcome {outcome}"),
        );
        if outcome == "RERUN_REQUIRED" {
            let command = optional_string(consumer, "command").unwrap_or("");
            push_error(
                &mut errors,
                is_remote_command(command),
                format!("{consumer_id} needs an exact remote command"),
            );
            push_error(
                &mut errors,
                command.contains(" cargo test ") || command.contains(" cargo run "),
                format!("{consumer_id} runtime profile cannot be compile-only"),
            );
            push_error(
                &mut errors,
                optional_string(consumer, "pinned_identity")
                    .is_some_and(|identity| !identity.trim().is_empty()),
                format!("{consumer_id} needs pinned provenance"),
            );
        } else {
            push_error(
                &mut errors,
                consumer.get("command").is_some_and(Value::is_null),
                format!("{consumer_id} blocked profile must not expose an executable command"),
            );
            push_error(
                &mut errors,
                optional_string(consumer, "blocker").is_some_and(|text| !text.trim().is_empty()),
                format!("{consumer_id} blocked profile needs a blocker"),
            );
        }
    }

    let projection = matrix
        .get("registry_consumer_projection")
        .expect("registry_consumer_projection");
    push_error(
        &mut errors,
        projection
            .get("expected_consumer_count")
            .and_then(Value::as_u64)
            .is_some_and(|count| count as usize == array(registry, "downstream_consumers").len()),
        "registry consumer projection count differs",
    );
    push_error(
        &mut errors,
        string(projection, "current_outcome") == "BLOCKED_EXTERNAL",
        "external registry consumers must remain BLOCKED_EXTERNAL",
    );

    validate_service_projection(matrix, service_matrix, &mut errors);
    errors
}

fn validate_service_projection(matrix: &Value, service_matrix: &Value, errors: &mut Vec<String>) {
    let projection = matrix
        .get("service_version_projection")
        .expect("service_version_projection");
    let expected_count = projection
        .get("expected_cell_count")
        .and_then(Value::as_u64)
        .expect("expected_cell_count") as usize;
    let mut cells = BTreeMap::new();
    for family in array(service_matrix, "service_families") {
        let family_id = string(family, "family_id");
        let directions = array(family, "directions");
        push_error(
            errors,
            !directions.is_empty(),
            format!("{family_id} must declare protocol directions"),
        );
        push_error(
            errors,
            family
                .get("restart_reconnect_required")
                .is_some_and(Value::is_boolean),
            format!("{family_id} must classify restart/reconnect"),
        );
        let family_outcome = string(family, "declared_outcome");
        if family_outcome == "EXECUTABLE_COMPLETE" {
            let provenance = family.get("provenance").expect("provenance");
            push_error(
                errors,
                optional_string(provenance, "version").is_some_and(|text| !text.trim().is_empty()),
                format!("{family_id} executable service lacks a pinned version"),
            );
            push_error(
                errors,
                optional_string(provenance, "identity").is_some_and(|text| !text.trim().is_empty()),
                format!("{family_id} executable service lacks immutable identity"),
            );
            push_error(
                errors,
                optional_string(family, "smoke_command").is_some_and(is_remote_command),
                format!("{family_id} executable service lacks an exact remote smoke command"),
            );
        } else {
            push_error(
                errors,
                matches!(family_outcome, "BLOCKED_EXTERNAL" | "UNSUPPORTED"),
                format!("{family_id} has unexpected service outcome {family_outcome}"),
            );
            push_error(
                errors,
                optional_string(family, "blocker").is_some_and(|text| !text.trim().is_empty()),
                format!("{family_id} blocked service needs a blocker"),
            );
        }
        for cell in array(family, "cells") {
            let cell_id = string(cell, "cell_id").to_owned();
            if cells
                .insert(cell_id.clone(), family_id.to_owned())
                .is_some()
            {
                errors.push(format!("duplicate service cell {cell_id}"));
            }
        }
    }
    push_error(
        errors,
        cells.len() == expected_count,
        format!(
            "service cell count {} must equal expected {expected_count}",
            cells.len()
        ),
    );
    for required in string_set(projection, "required_range_cells") {
        push_error(
            errors,
            cells.contains_key(&required),
            format!("missing required service range cell {required}"),
        );
    }
}

#[test]
fn matrix_covers_every_live_feature_capability_platform_consumer_and_service_cell() {
    let matrix = json(ARTIFACT_PATH);
    let registry = json(REGISTRY_PATH);
    let service_matrix = json(SERVICE_MATRIX_PATH);
    let features = cargo_feature_names();
    let errors = validate_matrix(&matrix, &registry, &service_matrix, &features);
    assert!(
        errors.is_empty(),
        "VER A5 matrix validation failed:\n{}",
        errors.join("\n")
    );

    let counts = matrix.get("counts").expect("counts");
    for (key, actual) in [
        ("cargo_features", features.len()),
        ("capabilities", array(&registry, "capabilities").len()),
        (
            "platform_selectors",
            registry_platform_selectors(&registry).len(),
        ),
        ("target_coordinates", array(&matrix, "target_catalog").len()),
        (
            "registry_consumers",
            array(&registry, "downstream_consumers").len(),
        ),
        (
            "maintained_consumer_profiles",
            array(&matrix, "maintained_consumer_profiles").len(),
        ),
        (
            "combination_profiles",
            array(&matrix, "combination_profiles").len(),
        ),
    ] {
        assert_eq!(
            counts.get(key).and_then(Value::as_u64),
            Some(actual as u64),
            "count mismatch for {key}"
        );
    }
}

#[test]
fn sparse_and_platform_negative_fixtures_fail_closed() {
    let base = json(ARTIFACT_PATH);
    let registry = json(REGISTRY_PATH);
    let services = json(SERVICE_MATRIX_PATH);
    let features = cargo_feature_names();

    let mut missing_feature = base.clone();
    missing_feature["sparse_feature_profiles"]
        .as_array_mut()
        .expect("profiles")
        .retain(|profile| profile["feature_id"].as_str() != Some("metrics"));
    let errors = validate_matrix(&missing_feature, &registry, &services, &features);
    assert!(
        errors
            .iter()
            .any(|error| error.contains("missing sparse feature profile metrics"))
    );

    let mut unified_substitute = base.clone();
    let profile = unified_substitute["sparse_feature_profiles"]
        .as_array_mut()
        .expect("profiles")
        .iter_mut()
        .find(|profile| profile["feature_id"].as_str() == Some("metrics"))
        .expect("metrics profile");
    profile["requested_features"] = serde_json::json!(["metrics", "tracing-integration"]);
    let errors = validate_matrix(&unified_substitute, &registry, &services, &features);
    assert!(
        errors
            .iter()
            .any(|error| error.contains("must select exactly one direct feature"))
    );

    let mut missing_selector = base.clone();
    missing_selector["platform_selector_expansions"]
        .as_array_mut()
        .expect("selectors")
        .retain(|row| row["selector"].as_str() != Some("windows"));
    let errors = validate_matrix(&missing_selector, &registry, &services, &features);
    assert!(
        errors
            .iter()
            .any(|error| error.contains("platform selectors differ"))
    );

    let mut host_target_confusion = base.clone();
    host_target_confusion["target_catalog"][0]["host_id"] =
        Value::String("linux-x86_64-gnu".to_owned());
    let errors = validate_matrix(&host_target_confusion, &registry, &services, &features);
    assert!(
        errors
            .iter()
            .any(|error| error.contains("references unknown host"))
    );

    let mut unsupported_as_pass = base;
    unsupported_as_pass["target_catalog"][4]["compile_outcome"] =
        Value::String("PASSED".to_owned());
    let errors = validate_matrix(&unsupported_as_pass, &registry, &services, &features);
    assert!(
        errors
            .iter()
            .any(|error| error.contains("uses forbidden outcome PASSED"))
    );
}

#[test]
fn consumer_and_service_negative_fixtures_fail_closed() {
    let base = json(ARTIFACT_PATH);
    let registry = json(REGISTRY_PATH);
    let services = json(SERVICE_MATRIX_PATH);
    let features = cargo_feature_names();

    let mut compile_only_consumer = base.clone();
    let consumer = compile_only_consumer["maintained_consumer_profiles"]
        .as_array_mut()
        .expect("consumers")
        .iter_mut()
        .find(|consumer| {
            consumer["consumer_profile_id"].as_str() == Some("downstream-stream-trait-consumer")
        })
        .expect("stream consumer");
    consumer["command"] = Value::String(
        "RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_TARGET_DIR=/tmp/ver-a5 cargo check -p asupersync"
            .to_owned(),
    );
    let errors = validate_matrix(&compile_only_consumer, &registry, &services, &features);
    assert!(
        errors
            .iter()
            .any(|error| error.contains("runtime profile cannot be compile-only"))
    );

    let mut unpinned_consumer = base.clone();
    unpinned_consumer["maintained_consumer_profiles"][0]["pinned_identity"] = Value::Null;
    let errors = validate_matrix(&unpinned_consumer, &registry, &services, &features);
    assert!(
        errors
            .iter()
            .any(|error| error.contains("needs pinned provenance"))
    );

    let mut unpinned_service = services.clone();
    let sqlite = unpinned_service["service_families"]
        .as_array_mut()
        .expect("families")
        .iter_mut()
        .find(|family| family["family_id"].as_str() == Some("sqlite"))
        .expect("sqlite family");
    sqlite["provenance"]["identity"] = Value::Null;
    let errors = validate_matrix(&base, &registry, &unpinned_service, &features);
    assert!(
        errors
            .iter()
            .any(|error| error.contains("executable service lacks immutable identity"))
    );

    let mut missing_range = services;
    let kafka = missing_range["service_families"]
        .as_array_mut()
        .expect("families")
        .iter_mut()
        .find(|family| family["family_id"].as_str() == Some("kafka"))
        .expect("kafka family");
    kafka["cells"]
        .as_array_mut()
        .expect("cells")
        .retain(|cell| cell["cell_id"].as_str() != Some("kafka-oldest-supported-plaintext"));
    let errors = validate_matrix(&base, &registry, &missing_range, &features);
    assert!(
        errors
            .iter()
            .any(|error| error.contains("missing required service range cell"))
    );
}

#[test]
fn docs_runner_and_negative_catalog_are_wired() {
    let matrix = json(ARTIFACT_PATH);
    for source_path in matrix
        .get("source_of_truth")
        .and_then(Value::as_object)
        .expect("source_of_truth")
        .values()
    {
        let path = source_path.as_str().expect("source path");
        assert!(repo_path(path).exists(), "source path must exist: {path}");
    }

    let docs = read_repo_file(DOCS_PATH);
    assert!(docs.contains(BEAD_ID));
    assert!(docs.contains(ARTIFACT_PATH));
    for marker in array(&matrix, "docs_markers") {
        let marker = marker.as_str().expect("docs marker");
        assert!(docs.contains(marker), "docs missing marker {marker}");
    }

    let runner = read_repo_file(RUNNER_PATH);
    for token in [
        "feature-platform-consumer-contract",
        "ver-a5-feature-platform-consumer-contract",
        ARTIFACT_PATH,
        "dependency_feature_platform_consumer_matrix_contract",
        BEAD_ID,
    ] {
        assert!(runner.contains(token), "runner missing token {token}");
    }

    let required_negative_fixtures = BTreeSet::from([
        "missing sparse feature profile",
        "sparse profile selects multiple direct features",
        "all-features substitutes for sparse profile",
        "missing optional feature edge",
        "unknown platform selector",
        "host ID used as a target ID",
        "target ID used as a host ID",
        "unsupported platform reported as pass",
        "runtime-required consumer uses compile-only command",
        "runtime-required consumer has no pinned identity",
        "unpinned executable service",
        "missing oldest/current service version cell",
        "external consumer absence reported as pass",
    ]);
    assert_eq!(
        string_set(&matrix, "negative_fixture_catalog")
            .iter()
            .map(String::as_str)
            .collect::<BTreeSet<_>>(),
        required_negative_fixtures
    );

    let validation = matrix.get("validation").expect("validation");
    assert!(is_remote_command(string(validation, "focused_command")));
    assert_eq!(
        string(validation, "canonical_scenario_id"),
        "feature-platform-consumer-contract"
    );
    assert_eq!(
        string(validation, "canonical_command"),
        "RCH_REQUIRE_REMOTE=1 bash scripts/run_dependency_sovereignty_e2e.sh --scenario feature-platform-consumer-contract"
    );
    assert_eq!(
        validation
            .get("no_local_cargo_fallback")
            .and_then(Value::as_bool),
        Some(true)
    );
}
