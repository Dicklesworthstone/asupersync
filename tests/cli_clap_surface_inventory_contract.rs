#![allow(missing_docs)]

use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

const ARTIFACT_PATH: &str = "artifacts/cli_clap_surface_inventory_v1.json";
const DOC_PATH: &str = "docs/cli_clap_surface_inventory.md";
const ADR_PATH: &str = "docs/adr/dep_plan_adr_005_cli_contract.md";
const ARTIFACT_ID: &str = "cli-clap-surface-inventory-v1";
const BEAD_ID: &str = "asupersync-5z2scg.7.1";
const ENV_LOGGER_BEAD_ID: &str = "asupersync-d24mms.3";
const DOC_BEGIN: &str = "<!-- BEGIN CLI CLAP SURFACE INVENTORY -->";
const DOC_END: &str = "<!-- END CLI CLAP SURFACE INVENTORY -->";

fn repo_path(relative: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(relative)
}

fn read_repo_bytes(relative: &str) -> Vec<u8> {
    std::fs::read(repo_path(relative)).unwrap_or_else(|error| panic!("read {relative}: {error}"))
}

fn read_repo_file(relative: &str) -> String {
    String::from_utf8(read_repo_bytes(relative))
        .unwrap_or_else(|error| panic!("{relative} must be UTF-8: {error}"))
}

fn repo_json(relative: &str) -> Value {
    serde_json::from_str(&read_repo_file(relative))
        .unwrap_or_else(|error| panic!("parse {relative}: {error}"))
}

fn array<'a>(value: &'a Value, key: &str) -> &'a [Value] {
    value
        .get(key)
        .and_then(Value::as_array)
        .map_or_else(|| panic!("{key} must be an array"), Vec::as_slice)
}

fn object<'a>(value: &'a Value, key: &str) -> &'a serde_json::Map<String, Value> {
    value
        .get(key)
        .and_then(Value::as_object)
        .unwrap_or_else(|| panic!("{key} must be an object"))
}

fn text<'a>(value: &'a Value, key: &str) -> &'a str {
    let result = value
        .get(key)
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("{key} must be a string"));
    assert!(!result.trim().is_empty(), "{key} must be nonempty");
    result
}

fn unsigned(value: &Value, key: &str) -> u64 {
    value
        .get(key)
        .and_then(Value::as_u64)
        .unwrap_or_else(|| panic!("{key} must be an unsigned integer"))
}

fn boolean(value: &Value, key: &str) -> bool {
    value
        .get(key)
        .and_then(Value::as_bool)
        .unwrap_or_else(|| panic!("{key} must be a bool"))
}

fn strings(value: &Value, key: &str) -> Vec<String> {
    array(value, key)
        .iter()
        .map(|entry| {
            entry
                .as_str()
                .filter(|item| !item.trim().is_empty())
                .unwrap_or_else(|| panic!("{key} entries must be nonempty strings"))
                .to_owned()
        })
        .collect()
}

fn string_set(value: &Value, key: &str) -> BTreeSet<String> {
    strings(value, key).into_iter().collect()
}

fn expected_set(values: &[&str]) -> BTreeSet<String> {
    values.iter().map(|value| (*value).to_owned()).collect()
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn count_attribute_starts(source: &str, attribute: &str) -> u64 {
    let prefix = format!("#[{attribute}");
    u64::try_from(
        source
            .lines()
            .filter(|line| line.trim_start().starts_with(&prefix))
            .count(),
    )
    .expect("attribute count fits u64")
}

fn count_derive(source: &str, derive_name: &str) -> u64 {
    u64::try_from(
        source
            .lines()
            .filter(|line| {
                let line = line.trim_start();
                line.starts_with("#[derive(") && line.contains(derive_name)
            })
            .count(),
    )
    .expect("derive count fits u64")
}

fn count_clap_env_attributes(source: &str) -> u64 {
    let mut in_arg = false;
    let mut count = 0_u64;
    for line in source.lines() {
        let trimmed = line.trim_start();
        if trimmed.starts_with("#[arg") {
            in_arg = true;
        }
        if in_arg && trimmed.contains("env =") {
            count += 1;
        }
        if in_arg && trimmed.contains(")]") {
            in_arg = false;
        }
    }
    count
}

fn count_trimmed_prefix(source: &str, prefix: &str) -> u64 {
    u64::try_from(
        source
            .lines()
            .filter(|line| line.trim_start().starts_with(prefix))
            .count(),
    )
    .expect("source marker count fits u64")
}

fn count_occurrences(source: &str, token: &str) -> u64 {
    u64::try_from(source.matches(token).count()).expect("source token count fits u64")
}

fn source_declares_type(source: &str, type_name: &str) -> bool {
    source.contains(&format!("struct {type_name}")) || source.contains(&format!("enum {type_name}"))
}

fn source_declares_variant(source: &str, variant: &str) -> bool {
    source.lines().any(|line| {
        let line = line.trim_start();
        line.strip_prefix(variant).is_some_and(|tail| {
            let tail = tail.trim_start();
            tail.starts_with('(') || tail.starts_with('{') || tail.starts_with(',')
        })
    })
}

fn find_primary<'a>(artifact: &'a Value, path: &str) -> &'a Value {
    array(artifact, "primary_sources")
        .iter()
        .find(|row| row.get("path").and_then(Value::as_str) == Some(path))
        .unwrap_or_else(|| panic!("missing primary source {path}"))
}

#[test]
fn source_pins_and_six_file_boundary_match_main() {
    let artifact = repo_json(ARTIFACT_PATH);
    assert_eq!(unsigned(&artifact, "schema_version"), 1);
    assert_eq!(text(&artifact, "artifact_id"), ARTIFACT_ID);
    assert_eq!(text(&artifact, "bead_id"), BEAD_ID);
    assert_eq!(text(&artifact, "base_commit").len(), 40);
    assert_eq!(
        text(&artifact, "disposition"),
        "STATIC_SURFACE_FROZEN_BYTE_GOLDENS_MISSING"
    );

    let pins = array(&artifact, "source_pins");
    assert_eq!(pins.len(), 13);
    let mut pinned_paths = BTreeSet::new();
    for pin in pins {
        let path = text(pin, "path");
        assert!(pinned_paths.insert(path.to_owned()), "duplicate pin {path}");
        assert!(!text(pin, "role").is_empty());
        let bytes = read_repo_bytes(path);
        assert_eq!(
            sha256_hex(&bytes),
            text(pin, "sha256"),
            "hash drift: {path}"
        );
        let source = std::str::from_utf8(&bytes).expect("pinned source must be UTF-8");
        assert_eq!(
            u64::try_from(source.lines().count()).expect("line count fits u64"),
            unsigned(pin, "line_count"),
            "line-count drift: {path}"
        );
    }

    let expected_primary = expected_set(&[
        "src/bin/asupersync.rs",
        "src/bin/atp.rs",
        "src/bin/atpd.rs",
        "src/bin/offline_tuner.rs",
        "src/cli/args.rs",
        "src/cli/atp_command_tree.rs",
    ]);
    let actual_primary = array(&artifact, "primary_sources")
        .iter()
        .map(|row| text(row, "path").to_owned())
        .collect::<BTreeSet<_>>();
    assert_eq!(actual_primary, expected_primary);
    assert!(expected_primary.is_subset(&pinned_paths));
    assert!(pinned_paths.contains("Cargo.toml"));
    assert!(pinned_paths.contains("src/cli/output.rs"));
    assert!(pinned_paths.contains("src/cli/exit.rs"));
    assert!(pinned_paths.contains("src/cli/mod.rs"));
    assert!(pinned_paths.contains("src/cli/atp_workflows.rs"));
}

#[test]
fn declaration_indexes_and_annotation_counts_are_exact() {
    let artifact = repo_json(ARTIFACT_PATH);
    let expected = [
        ("src/bin/asupersync.rs", 1, 10, 52, 4, 174, 12, 3),
        ("src/bin/atp.rs", 7, 1, 0, 4, 99, 8, 0),
        ("src/bin/atpd.rs", 1, 2, 3, 0, 18, 5, 0),
        ("src/bin/offline_tuner.rs", 1, 1, 0, 1, 15, 4, 3),
        ("src/cli/args.rs", 0, 0, 4, 0, 20, 0, 0),
        ("src/cli/atp_command_tree.rs", 0, 6, 47, 2, 164, 5, 0),
    ];

    for (path, parsers, subcommands, args, values, arg_attrs, command_attrs, value_attrs) in
        expected
    {
        let row = find_primary(&artifact, path);
        let counts = Value::Object(object(row, "annotation_counts").clone());
        let source = read_repo_file(path);
        assert_eq!(
            count_derive(&source, "Parser"),
            parsers,
            "Parser drift: {path}"
        );
        assert_eq!(
            count_derive(&source, "Subcommand"),
            subcommands,
            "Subcommand drift: {path}"
        );
        assert_eq!(count_derive(&source, "Args"), args, "Args drift: {path}");
        assert_eq!(
            count_derive(&source, "ValueEnum"),
            values,
            "ValueEnum drift: {path}"
        );
        assert_eq!(
            count_attribute_starts(&source, "arg"),
            arg_attrs,
            "arg drift: {path}"
        );
        assert_eq!(
            count_attribute_starts(&source, "command"),
            command_attrs,
            "command drift: {path}"
        );
        assert_eq!(
            count_attribute_starts(&source, "value"),
            value_attrs,
            "value drift: {path}"
        );
        assert_eq!(
            count_clap_env_attributes(&source),
            0,
            "clap env binding: {path}"
        );
        assert_eq!(unsigned(&counts, "derive_parser"), parsers);
        assert_eq!(unsigned(&counts, "derive_subcommand"), subcommands);
        assert_eq!(unsigned(&counts, "derive_args"), args);
        assert_eq!(unsigned(&counts, "derive_value_enum"), values);
        assert_eq!(unsigned(&counts, "arg_attributes"), arg_attrs);
        assert_eq!(unsigned(&counts, "command_attributes"), command_attrs);
        assert_eq!(unsigned(&counts, "value_attributes"), value_attrs);
        assert_eq!(unsigned(&counts, "clap_env_attributes"), 0);

        for key in [
            "parser_derived_types",
            "argument_group_types",
            "value_enums",
        ] {
            for type_name in strings(row, key) {
                assert!(
                    source_declares_type(&source, &type_name),
                    "{path} does not declare indexed {key} type {type_name}"
                );
            }
        }
        if let Some(root) = row.get("root_parser").and_then(Value::as_str) {
            assert!(
                source_declares_type(&source, root),
                "missing root parser {root}"
            );
        }
    }
}

#[test]
fn every_indexed_command_variant_is_present_and_reachability_is_explicit() {
    let artifact = repo_json(ARTIFACT_PATH);
    let mut total_variants = 0_u64;
    let mut binary_variants = 0_u64;

    for row in array(&artifact, "primary_sources") {
        let path = text(row, "path");
        let source = read_repo_file(path);
        let mut row_variants = 0_u64;
        for command_enum in array(row, "subcommand_enums") {
            let rust_type = text(command_enum, "rust_type");
            assert!(
                source.contains(&format!("enum {rust_type}")),
                "missing enum {rust_type}"
            );
            let variants = strings(command_enum, "variants");
            let unique = variants.iter().collect::<BTreeSet<_>>();
            assert_eq!(
                unique.len(),
                variants.len(),
                "duplicate variants in {path}:{rust_type}"
            );
            for mapping in &variants {
                let (rust_variant, clap_name) = mapping
                    .split_once('=')
                    .unwrap_or_else(|| panic!("invalid variant mapping {mapping}"));
                assert!(!clap_name.is_empty(), "empty clap name in {mapping}");
                assert!(
                    source_declares_variant(&source, rust_variant),
                    "missing variant {rust_variant} in {path}"
                );
            }
            row_variants += u64::try_from(variants.len()).expect("variant count fits u64");
        }
        assert_eq!(
            row_variants,
            unsigned(row, "command_variant_count"),
            "{path}"
        );
        total_variants += row_variants;
        if row.get("binary").is_some_and(Value::is_string) {
            binary_variants += row_variants;
        }
    }

    assert_eq!(total_variants, 159);
    assert_eq!(binary_variants, 108);
    let detached = find_primary(&artifact, "src/cli/atp_command_tree.rs");
    assert_eq!(
        text(detached, "reachability"),
        "LIBRARY_EXPORTED_NO_BINARY_PARSER_ROOT"
    );
    assert!(array(detached, "binary_consumers").is_empty());
    assert_eq!(
        string_set(detached, "library_consumers"),
        expected_set(&["src/cli/atp_config.rs", "src/cli/atp_workflows.rs"])
    );
    for binary in [
        "src/bin/asupersync.rs",
        "src/bin/atp.rs",
        "src/bin/atpd.rs",
        "src/bin/offline_tuner.rs",
    ] {
        assert!(!read_repo_file(binary).contains("atp_command_tree"));
    }
}

#[test]
fn complete_field_normalization_cohort_is_exact_and_source_anchored() {
    let artifact = repo_json(ARTIFACT_PATH);
    let scope = Value::Object(object(&artifact, "scope").clone());
    assert_eq!(
        text(&scope, "argument_surface_state"),
        "FIELD_NORMALIZED_FOR_6_OF_6_PRIMARY_SOURCES"
    );
    let normalization = Value::Object(object(&artifact, "field_normalization").clone());
    assert_eq!(
        text(&normalization, "status"),
        "COMPLETE_6_OF_6_PRIMARY_SOURCES"
    );
    assert_eq!(
        string_set(&normalization, "normalized_primary_sources"),
        expected_set(&[
            "src/bin/asupersync.rs",
            "src/bin/atp.rs",
            "src/bin/atpd.rs",
            "src/bin/offline_tuner.rs",
            "src/cli/args.rs",
            "src/cli/atp_command_tree.rs",
        ])
    );
    assert!(array(&normalization, "remaining_primary_sources").is_empty());
    assert_eq!(
        unsigned(&normalization, "annotated_arg_attribute_count"),
        490
    );
    assert_eq!(unsigned(&normalization, "implicit_positional_count"), 37);
    assert_eq!(unsigned(&normalization, "normalized_field_count"), 527);
    assert!(text(&normalization, "spelling_policy").contains("not byte-capture evidence"));

    let rows = array(&normalization, "rows");
    assert_eq!(rows.len(), 527);
    for (path, expected_count) in [
        ("src/bin/asupersync.rs", 199_usize),
        ("src/bin/atp.rs", 109_usize),
        ("src/bin/atpd.rs", 20_usize),
        ("src/bin/offline_tuner.rs", 15),
        ("src/cli/args.rs", 20),
        ("src/cli/atp_command_tree.rs", 164),
    ] {
        assert_eq!(
            rows.iter()
                .filter(|row| row.get("source_path").and_then(Value::as_str) == Some(path))
                .count(),
            expected_count,
            "normalized row count drift: {path}"
        );
    }
    assert_eq!(
        rows.iter()
            .filter(|row| {
                row.get("source_path").and_then(Value::as_str) == Some("src/bin/atp.rs")
                    && row
                        .get("consumer_state")
                        .and_then(Value::as_str)
                        .is_some_and(|state| state.starts_with("STRUCT_DISPATCHED_TO_"))
            })
            .count(),
        108
    );
    assert_eq!(
        rows.iter()
            .filter(|row| {
                row.get("source_path").and_then(Value::as_str) == Some("src/bin/atp.rs")
                    && row.get("consumer_state").and_then(Value::as_str)
                        == Some("CONSUMED_BY_EXPORT_DELTA_STATE")
            })
            .count(),
        1
    );
    assert_eq!(
        rows.iter()
            .filter(|row| {
                row.get("source_path").and_then(Value::as_str) == Some("src/bin/asupersync.rs")
                    && row.get("source_attribute").and_then(Value::as_str)
                        != Some("NONE_IMPLICIT_POSITIONAL")
            })
            .count(),
        174
    );
    assert_eq!(
        rows.iter()
            .filter(|row| {
                row.get("source_path").and_then(Value::as_str) == Some("src/bin/asupersync.rs")
                    && row.get("source_attribute").and_then(Value::as_str)
                        == Some("NONE_IMPLICIT_POSITIONAL")
            })
            .count(),
        25
    );
    assert_eq!(
        rows.iter()
            .filter(|row| {
                row.get("source_path").and_then(Value::as_str) == Some("src/bin/atp.rs")
                    && row.get("rust_field").and_then(Value::as_str) == Some("max_block_size")
                    && row
                        .get("source_attribute")
                        .and_then(Value::as_str)
                        .is_some_and(|attribute| {
                            attribute.contains("value_parser = parse_max_block_size_arg")
                        })
            })
            .count(),
        6
    );
    assert_eq!(
        rows.iter()
            .filter(|row| {
                row.get("source_path").and_then(Value::as_str)
                    == Some("src/cli/atp_command_tree.rs")
                    && row.get("consumer_state").and_then(Value::as_str)
                        == Some("DETACHED_PUBLIC_COMMAND_MODEL_NO_BINARY_PARSER_ROOT")
            })
            .count(),
        60
    );
    assert_eq!(
        rows.iter()
            .filter(|row| {
                row.get("source_path").and_then(Value::as_str)
                    == Some("src/cli/atp_command_tree.rs")
                    && row.get("consumer_state").and_then(Value::as_str)
                        == Some("DETACHED_LIBRARY_WORKFLOW_MODEL_NO_BINARY_PARSER_ROOT")
            })
            .count(),
        104
    );

    let mut field_ids = BTreeSet::new();
    let mut annotated = 0_u64;
    let mut implicit = 0_u64;
    let mut parsed_unused = BTreeSet::new();
    for row in rows {
        let field_id = text(row, "field_id");
        assert!(
            field_ids.insert(field_id.to_owned()),
            "duplicate field id {field_id}"
        );
        let path = text(row, "source_path");
        let source = read_repo_file(path);
        for key in [
            "owner_type",
            "rust_field",
            "field_declaration",
            "cli_spelling",
            "argument_kind",
            "spelling_basis",
            "field_type",
            "source_default",
            "cardinality",
            "scope",
            "consumer_state",
        ] {
            assert!(!text(row, key).is_empty(), "{field_id} missing {key}");
        }
        assert!(
            source.contains(text(row, "field_declaration")),
            "{field_id} field declaration drift"
        );
        let source_attribute = text(row, "source_attribute");
        if source_attribute == "NONE_IMPLICIT_POSITIONAL" {
            implicit += 1;
            assert_eq!(text(row, "argument_kind"), "POSITIONAL");
            assert!(text(row, "spelling_basis").starts_with("IMPLICIT_POSITIONAL"));
        } else {
            annotated += 1;
            assert!(
                source.contains(source_attribute),
                "{field_id} source attribute drift"
            );
        }
        assert!(
            !array(row, "consumer_anchors").is_empty(),
            "{field_id} needs a consumer or gap anchor"
        );
        if text(row, "consumer_state") == "PARSED_UNUSED_GAP" {
            parsed_unused.insert(field_id.to_owned());
        }
    }
    assert_eq!(annotated, 490);
    assert_eq!(implicit, 37);
    assert_eq!(
        parsed_unused,
        expected_set(&[
            "CLI-ASUP-DOCTOR-RECIPE-LIST-JSON",
            "CLI-ATPD-ROOT-FOREGROUND",
        ])
    );

    let gaps = array(&normalization, "observed_gaps");
    assert_eq!(
        gaps.iter()
            .map(|row| text(row, "gap_id").to_owned())
            .collect::<BTreeSet<_>>(),
        expected_set(&[
            "CLI-FIELD-GAP-01",
            "CLI-FIELD-GAP-02",
            "CLI-FIELD-GAP-03",
            "CLI-FIELD-GAP-04",
            "CLI-FIELD-GAP-05",
            "CLI-FIELD-GAP-06",
            "CLI-FIELD-GAP-07",
            "CLI-FIELD-GAP-08",
            "CLI-FIELD-GAP-09",
            "CLI-FIELD-GAP-10",
            "CLI-FIELD-GAP-11",
            "CLI-FIELD-GAP-12",
            "CLI-FIELD-GAP-13",
            "CLI-FIELD-GAP-14",
        ])
    );
    for gap in gaps {
        assert!(text(gap, "state").starts_with("SOURCE_OBSERVED"));
        assert!(!text(gap, "contract").is_empty());
        assert!(!array(gap, "anchors").is_empty());
    }
}

#[test]
fn feature_environment_config_and_exit_boundaries_fail_closed() {
    let artifact = repo_json(ARTIFACT_PATH);
    let authority = Value::Object(object(&artifact, "authority").clone());
    assert_eq!(text(&authority, "dependency_decision"), "KEEP_UNTIL_PARITY");
    for key in [
        "dependency_exit_allowed",
        "parser_replacement_allowed",
        "command_or_option_removal_allowed",
    ] {
        assert!(!boolean(&authority, key), "{key} must remain false");
    }

    let ids = array(&artifact, "cross_file_contracts")
        .iter()
        .map(|row| text(row, "contract_id").to_owned())
        .collect::<BTreeSet<_>>();
    assert_eq!(
        ids,
        expected_set(&[
            "CLI-WIDTH-01",
            "CLI-ENV-01",
            "CLI-OUTPUT-01",
            "CLI-CONFIG-01",
            "CLI-CONFIG-02",
            "CLI-CONFIG-03",
            "CLI-ENV-ATP-01",
            "CLI-ENV-ATPD-01",
            "CLI-ENV-TUNER-01",
            "CLI-EXIT-01",
            "CLI-REACHABILITY-01",
        ])
    );
    for row in array(&artifact, "cross_file_contracts") {
        assert!(text(row, "state").starts_with("SOURCE_OBSERVED"));
        assert!(!text(row, "contract").is_empty());
        assert!(!array(row, "anchors").is_empty());
    }

    let manifest = read_repo_file("Cargo.toml");
    assert!(
        manifest.contains("clap = { version = \"4.4\", features = [\"derive\"], optional = true }")
    );
    assert!(!manifest.contains("wrap_help"));
    assert!(manifest.contains("required-features = [\"cli\"]"));
    assert!(manifest.contains("required-features = [\"atp-cli\"]"));
    assert!(manifest.contains("required-features = [\"atpd-daemon\"]"));
    assert!(manifest.contains("required-features = [\"cli\", \"simd-intrinsics\"]"));

    let asupersync = read_repo_file("src/bin/asupersync.rs");
    assert!(asupersync.contains("config: self.config.clone()"));
    assert!(asupersync.contains("let format = effective_output_format"));
    assert!(asupersync.contains("let run_result = run(cli.command, &mut output)"));
    let output = read_repo_file("src/cli/output.rs");
    for marker in [
        "CI",
        "ASUPERSYNC_OUTPUT_FORMAT",
        "NO_COLOR",
        "CLICOLOR_FORCE",
    ] {
        assert!(
            output.contains(marker),
            "missing output environment marker {marker}"
        );
    }
    let atp = read_repo_file("src/bin/atp.rs");
    for marker in [
        "ATP_RQ_AUTH_KEY_HEX",
        "SSL_CERT_FILE",
        "SSL_CERT_DIR",
        "HOME",
    ] {
        assert!(
            atp.contains(marker),
            "missing ATP environment marker {marker}"
        );
    }
    let atpd = read_repo_file("src/bin/atpd.rs");
    for marker in ["PROGRAMDATA", "HOSTNAME", "COMPUTERNAME"] {
        assert!(
            atpd.contains(marker),
            "missing ATPD environment marker {marker}"
        );
    }
    let tuner = read_repo_file("src/bin/offline_tuner.rs");
    assert!(tuner.contains("env_logger::Builder::from_env"));
    assert!(tuner.contains("env_logger::Env::default()"));
}

#[test]
fn offline_tuner_env_logger_audit_is_source_pinned_and_fail_closed() {
    let artifact = repo_json(ARTIFACT_PATH);
    let audit = Value::Object(object(&artifact, "env_logger_static_audit").clone());
    assert_eq!(
        text(&audit, "audit_id"),
        "CLI-OFFLINE-TUNER-ENV-LOGGER-AUDIT-V1"
    );
    assert_eq!(text(&audit, "bead_id"), ENV_LOGGER_BEAD_ID);
    assert_eq!(
        string_set(&audit, "capability_ids"),
        expected_set(&["CAP-CLI-OFFLINE-TUNER", "CAP-DIAGNOSTICS"])
    );
    assert_eq!(
        text(&audit, "audit_state"),
        "STATIC_SOURCE_PINNED_NOT_EXECUTED"
    );
    assert_eq!(
        text(&audit, "execution_state"),
        "NO_BLACK_BOX_BASELINE_CAPTURED"
    );

    let decision = Value::Object(object(&audit, "decision").clone());
    assert_eq!(text(&decision, "dependency"), "env_logger");
    assert_eq!(text(&decision, "disposition"), "KEEP_INCUMBENT");
    for key in [
        "dependency_exit_allowed",
        "manifest_or_lockfile_edit_allowed",
        "source_behavior_change_allowed",
    ] {
        assert!(!boolean(&decision, key), "{key} must remain false");
    }
    assert!(text(&decision, "reason").contains("black-box baseline is absent"));

    let pins = array(&audit, "source_pins");
    assert_eq!(pins.len(), 6);
    let mut pinned_paths = BTreeSet::new();
    for pin in pins {
        let path = text(pin, "path");
        assert!(
            pinned_paths.insert(path.to_owned()),
            "duplicate audit pin {path}"
        );
        let bytes = read_repo_bytes(path);
        assert_eq!(
            sha256_hex(&bytes),
            text(pin, "sha256"),
            "audit hash drift: {path}"
        );
        let source = std::str::from_utf8(&bytes).expect("audit source must be UTF-8");
        assert_eq!(
            u64::try_from(source.lines().count()).expect("line count fits u64"),
            unsigned(pin, "line_count"),
            "audit line-count drift: {path}"
        );
        assert!(!text(pin, "role").is_empty());
    }
    assert_eq!(
        pinned_paths,
        expected_set(&[
            "Cargo.toml",
            "Cargo.lock",
            "src/bin/offline_tuner.rs",
            "src/raptorq/offline_tuner.rs",
            "scripts/run_offline_tuning.sh",
            "scripts/run_scheduler_recommend_smoke.sh",
        ])
    );

    let correction = Value::Object(object(&audit, "source_pin_measurement_correction").clone());
    assert_eq!(text(&correction, "captured_date_utc"), "2026-08-05");
    assert_eq!(
        text(&correction, "base_commit"),
        "74d7a9a5d8a8931c1165c6df42ea021714150dea"
    );
    assert_eq!(text(&correction, "path"), "scripts/run_offline_tuning.sh");
    assert_eq!(
        text(&correction, "sha256"),
        "5092520cbad3aa6289baf4d5e9ce5f135f189fc504c82f00aca2d7382f130836"
    );
    assert_eq!(unsigned(&correction, "previous_line_count"), 247);
    assert_eq!(unsigned(&correction, "corrected_line_count"), 248);
    assert!(text(&correction, "line_count_semantics").contains("Rust str::lines()"));
    assert!(!boolean(&correction, "source_ends_with_lf"));
    assert!(!boolean(&correction, "source_bytes_changed"));
    assert!(!boolean(&correction, "decision_changed"));
    assert_eq!(text(&correction, "execution_state"), "NOT_RUN_STATIC_ONLY");
    assert!(text(&correction, "no_claim_boundary").contains("does not execute"));
    assert!(text(&correction, "no_claim_boundary").contains("KEEP_INCUMBENT"));
    assert!(text(&correction, "no_claim_boundary").contains("dependency exit"));

    let corrected_source = read_repo_bytes("scripts/run_offline_tuning.sh");
    assert!(!corrected_source.ends_with(b"\n"));
    let corrected_source =
        std::str::from_utf8(&corrected_source).expect("corrected source pin must remain UTF-8");
    assert_eq!(corrected_source.lines().count(), 248);

    let observed = Value::Object(object(&audit, "observed_source_contract").clone());
    assert_eq!(text(&observed, "binary"), "offline_tuner");
    assert_eq!(
        string_set(&observed, "required_features"),
        expected_set(&["cli", "simd-intrinsics"])
    );
    let expected_commands = expected_set(&[
        "optimize",
        "candidates",
        "emit-profile",
        "validate",
        "scheduler-recommend",
    ]);
    assert_eq!(string_set(&observed, "commands"), expected_commands);
    assert_eq!(array(&observed, "initialization_order").len(), 5);

    let manifest_boundary = Value::Object(object(&observed, "manifest_boundary").clone());
    for key in [
        "cli_enables_env_logger",
        "env_logger_optional_dependency",
        "tracing_integration_also_enabled_by_cli",
    ] {
        assert!(boolean(&manifest_boundary, key), "{key} must remain true");
    }
    assert!(!boolean(
        &manifest_boundary,
        "static_graph_equivalence_proved"
    ));
    assert_eq!(
        text(&manifest_boundary, "locked_env_logger_version"),
        "0.11.11"
    );

    let binary = read_repo_file("src/bin/offline_tuner.rs");
    let tuner_module = read_repo_file("src/raptorq/offline_tuner.rs");
    let counts = Value::Object(object(&observed, "logging_and_output_counts").clone());
    assert_eq!(
        unsigned(&counts, "env_logger_builder_initializers"),
        count_occurrences(&binary, "env_logger::Builder::from_env")
    );
    assert_eq!(
        unsigned(&counts, "env_default_lookups"),
        count_occurrences(&binary, "env_logger::Env::default")
    );
    assert_eq!(
        unsigned(&counts, "stdout_print_macro_sites_in_binary"),
        count_trimmed_prefix(&binary, "println!")
    );
    assert_eq!(
        unsigned(&counts, "stderr_print_macro_sites_in_binary"),
        count_trimmed_prefix(&binary, "eprintln!")
    );
    assert_eq!(
        unsigned(&counts, "explicit_exit_one_sites_in_binary"),
        count_occurrences(&binary, "process::exit(1)")
    );
    assert_eq!(
        unsigned(&counts, "filesystem_write_sites_in_binary"),
        count_occurrences(&binary, "fs::write")
    );
    assert_eq!(
        unsigned(&counts, "filesystem_read_sites_in_binary"),
        count_occurrences(&binary, "fs::read_to_string")
    );
    assert_eq!(
        unsigned(&counts, "wall_clock_artifact_sites_in_binary"),
        count_occurrences(&binary, "SystemTime::now")
    );
    let direct_logging_tokens = [
        "log::",
        "tracing::",
        "trace!",
        "debug!",
        "info!",
        "warn!",
        "error!",
    ]
    .iter()
    .map(|token| count_occurrences(&binary, token) + count_occurrences(&tuner_module, token))
    .sum::<u64>();
    assert_eq!(
        unsigned(
            &counts,
            "direct_log_or_tracing_tokens_in_binary_and_tuner_module"
        ),
        direct_logging_tokens
    );
    assert_eq!(direct_logging_tokens, 0);
    assert!(
        text(&observed, "source_only_interpretation").contains("does not prove that dependencies")
    );

    let manifest = read_repo_file("Cargo.toml");
    assert!(manifest.contains("\"dep:env_logger\""));
    assert!(manifest.contains("env_logger = { version = \"0.11\", optional = true }"));
    assert!(manifest.contains("required-features = [\"cli\", \"simd-intrinsics\"]"));
    let lock = read_repo_file("Cargo.lock");
    assert!(lock.contains("name = \"env_logger\"\nversion = \"0.11.11\""));

    let baseline = Value::Object(object(&audit, "required_black_box_baseline").clone());
    assert_eq!(text(&baseline, "status"), "MISSING_NOT_RUN");
    assert_eq!(unsigned(&baseline, "captured_case_count"), 0);
    assert!(array(&baseline, "captured_cases").is_empty());
    assert_eq!(unsigned(&baseline, "nominal_filter_matrix_cell_count"), 30);
    assert_eq!(string_set(&baseline, "commands"), expected_commands);
    assert_eq!(array(&baseline, "verbosity_cells").len(), 2);
    assert_eq!(array(&baseline, "rust_log_cells").len(), 3);
    assert_eq!(array(&baseline, "required_outcome_classes").len(), 5);
    assert_eq!(array(&baseline, "required_record_fields").len(), 13);
    assert!(text(&baseline, "missing_or_unsupported_policy").contains("keeps env_logger"));

    let cutover = Value::Object(object(&audit, "cutover_gate").clone());
    assert_eq!(text(&cutover, "required_state"), "SAME_OR_BETTER");
    assert_eq!(
        array(&cutover, "rows")
            .iter()
            .map(|row| text(row, "row_id").to_owned())
            .collect::<BTreeSet<_>>(),
        expected_set(&[
            "ENVLOG-BASELINE-ALL-COMMANDS",
            "ENVLOG-FILTER-PARITY",
            "ENVLOG-STREAM-EXIT-PARITY",
            "ENVLOG-ARTIFACT-REPLAY-PARITY",
            "ENVLOG-REDACTION-PARITY",
            "ENVLOG-REPLACEMENT-UNIT-EVIDENCE",
            "ENVLOG-DEPENDENCY-LEDGER-CUTOVER",
        ])
    );
    for row in array(&cutover, "rows") {
        assert_eq!(text(row, "state"), "MISSING");
        assert!(!text(row, "requirement").is_empty());
    }
    assert_eq!(
        text(&cutover, "on_any_missing_or_regressed_row"),
        "KEEP_INCUMBENT"
    );
    assert!(!boolean(&cutover, "dependency_exit_allowed"));
    assert!(!boolean(&cutover, "tracker_closure_allowed"));

    let no_claims = strings(&audit, "no_claims").join("\n");
    for marker in [
        "No offline_tuner command",
        "not proof that the built dependency graph emits no records",
        "future evidence obligation",
        "No stdout, stderr, exit, panic",
        "does not authorize env_logger removal",
    ] {
        assert!(
            no_claims.contains(marker),
            "missing env_logger no-claim marker {marker}"
        );
    }
}

#[test]
fn byte_golden_matrix_is_required_but_not_fabricated() {
    let artifact = repo_json(ARTIFACT_PATH);
    let capture = Value::Object(object(&artifact, "golden_capture_contract").clone());
    assert_eq!(text(&capture, "status"), "MISSING_EXECUTION_RECEIPTS");
    assert_eq!(unsigned(&capture, "captured_case_count"), 0);
    assert!(array(&capture, "captured_cases").is_empty());
    assert!(!boolean(&capture, "allow_source_inference_as_bytes"));
    assert_eq!(array(&capture, "required_record_fields").len(), 11);
    assert_eq!(array(&capture, "required_case_classes").len(), 14);
    assert_eq!(array(&capture, "terminal_contexts").len(), 7);

    let matrix = array(&capture, "binary_matrix");
    assert_eq!(matrix.len(), 4);
    let binaries = matrix
        .iter()
        .map(|row| text(row, "binary").to_owned())
        .collect::<BTreeSet<_>>();
    assert_eq!(
        binaries,
        expected_set(&["asupersync", "atp", "atpd", "offline_tuner"])
    );
    assert_eq!(
        matrix
            .iter()
            .map(|row| unsigned(row, "command_variant_count"))
            .sum::<u64>(),
        108
    );
    for row in matrix {
        assert_eq!(text(row, "state"), "MISSING");
        assert!(!array(row, "required_features").is_empty());
        assert!(!array(row, "platform_cells").is_empty());
    }

    let no_claims = strings(&artifact, "no_claims").join("\n");
    for marker in [
        "No byte-level help",
        "No binary or parser was executed",
        "Field normalization covers all six primary sources",
        "does not authorize clap replacement",
        "does not prove compilation",
    ] {
        assert!(
            no_claims.contains(marker),
            "missing no-claim marker {marker}"
        );
    }
}

#[test]
fn documentation_and_adr_keep_the_static_completion_boundary_visible() {
    let docs = read_repo_file(DOC_PATH);
    let begin = docs.find(DOC_BEGIN).expect("documentation begin marker");
    let end = docs.find(DOC_END).expect("documentation end marker");
    assert!(begin < end);
    for marker in [
        ARTIFACT_ID,
        BEAD_ID,
        "159",
        "108",
        "527",
        "490",
        "164",
        "60",
        "104",
        "199",
        "109",
        "COMPLETE_6_OF_6_PRIMARY_SOURCES",
        "PARSED_UNUSED_GAP",
        "zero captured byte goldens",
        "LIBRARY_EXPORTED_NO_BINARY_PARSER_ROOT",
        "MISSING_EXECUTION_RECEIPTS",
        "KEEP_UNTIL_PARITY",
        ENV_LOGGER_BEAD_ID,
        "CLI-OFFLINE-TUNER-ENV-LOGGER-AUDIT-V1",
        "NO_BLACK_BOX_BASELINE_CAPTURED",
        "KEEP_INCUMBENT",
        "no final LF",
        "line 248",
        "dependency_exit_allowed=false",
    ] {
        assert!(docs.contains(marker), "documentation missing {marker}");
    }

    let adr = read_repo_file(ADR_PATH);
    for marker in [
        ARTIFACT_PATH,
        DOC_PATH,
        "STATIC_SURFACE_FROZEN_BYTE_GOLDENS_MISSING",
        "COMPLETE_6_OF_6_PRIMARY_SOURCES",
        "527",
        "MISSING_EXECUTION_RECEIPTS",
    ] {
        assert!(adr.contains(marker), "ADR missing {marker}");
    }
}
