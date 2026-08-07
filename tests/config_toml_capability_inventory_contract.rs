//! Fail-closed TOML/config capability inventory contract.
//!
//! Beads: asupersync-5z2scg.4.1, asupersync-5z2scg.4.2,
//! asupersync-5z2scg.4.3
//! Scenario: config-toml-capability-inventory-contract
//! Fixture: artifacts/config_toml_capability_inventory_v1.json
//!
//! This proves source-pinned surface, field, grammar, precedence, I/O, error,
//! corpus, downstream, child-owner, and gap inventories, plus the fail-closed
//! A2 source-implementation receipt, and A3 incumbent-preservation receipt. It
//! does not prove arbitrary TOML or JSON, real binary journeys, execution of
//! the A2 source tests or this contract, or permission to remove the incumbent
//! `toml` dependency.

#![allow(missing_docs)]

use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::path::PathBuf;

const ARTIFACT_PATH: &str = "artifacts/config_toml_capability_inventory_v1.json";
const DOC_PATH: &str = "docs/config_toml_capability_inventory.md";
const ADR_PATH: &str = "docs/adr/dep_plan_adr_004_config_scenario_formats.md";
const CAPABILITY_REGISTRY_PATH: &str = "artifacts/dependency_capability_registry_v1.json";
const API_SURFACE_MAP_PATH: &str = "artifacts/api_surface_map_v1.json";
const BEAD_ID: &str = "asupersync-5z2scg.4.1";
const A2_BEAD_ID: &str = "asupersync-5z2scg.4.2";
const A3_BEAD_ID: &str = "asupersync-5z2scg.4.3";
const A5_BEAD_ID: &str = "asupersync-5z2scg.4.5";
const PROGRAM_ID: &str = "asupersync-ir2uf0";
const CAPABILITY_ID: &str = "CAP-CONFIG-TOML-JSON";
const ADR_ID: &str = "DEP-ADR-004";
const BASELINE_REVISION: &str = "3468d4474e981fd2b19a8020175e6bb8bd4a5dc3";
const AUTHORITY_REVISION: &str = "673a905631c5580cdc8037315569b72bd636ecca";
const DOC_BEGIN: &str = "<!-- BEGIN CONFIG TOML CAPABILITY INVENTORY -->";
const DOC_END: &str = "<!-- END CONFIG TOML CAPABILITY INVENTORY -->";

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn read_repo_file(path: &str) -> String {
    std::fs::read_to_string(repo_root().join(path))
        .unwrap_or_else(|error| panic!("failed to read {path}: {error}"))
}

fn read_repo_bytes(path: &str) -> Vec<u8> {
    std::fs::read(repo_root().join(path))
        .unwrap_or_else(|error| panic!("failed to read {path}: {error}"))
}

fn parse_repo_json(path: &str) -> Value {
    serde_json::from_str(&read_repo_file(path))
        .unwrap_or_else(|error| panic!("{path} must be valid JSON: {error}"))
}

fn artifact() -> Value {
    parse_repo_json(ARTIFACT_PATH)
}

fn array<'a>(value: &'a Value, key: &str) -> &'a Vec<Value> {
    value
        .get(key)
        .and_then(Value::as_array)
        .unwrap_or_else(|| panic!("{key} must be an array"))
}

fn object<'a>(value: &'a Value, key: &str) -> &'a serde_json::Map<String, Value> {
    value
        .get(key)
        .and_then(Value::as_object)
        .unwrap_or_else(|| panic!("{key} must be an object"))
}

fn text<'a>(value: &'a Value, key: &str) -> &'a str {
    value
        .get(key)
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("{key} must be a string"))
}

fn row_ids(rows: &[Value], key: &str) -> BTreeSet<String> {
    rows.iter().map(|row| text(row, key).to_owned()).collect()
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

fn find_row<'a>(rows: &'a [Value], key: &str, expected: &str) -> &'a Value {
    rows.iter()
        .find(|row| row.get(key).and_then(Value::as_str) == Some(expected))
        .unwrap_or_else(|| panic!("missing {key}={expected}"))
}

fn validate_state_fields(value: &Value, path: &str) -> Result<(), String> {
    match value {
        Value::Array(values) => {
            for (index, child) in values.iter().enumerate() {
                validate_state_fields(child, &format!("{path}[{index}]"))?;
            }
        }
        Value::Object(values) => {
            for (key, child) in values {
                let child_path = format!("{path}.{key}");
                if matches!(key.as_str(), "inventory_state" | "evidence_state")
                    && child.as_str() == Some("UNKNOWN")
                {
                    return Err(format!("{child_path} must not be UNKNOWN"));
                }
                validate_state_fields(child, &child_path)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn validate_post_a3_provenance_refresh(inventory: &Value) -> Result<(), String> {
    let refresh = inventory
        .get("post_a3_provenance_refresh")
        .ok_or_else(|| "post_a3_provenance_refresh must be present".to_owned())?;
    for (key, expected) in [
        ("captured_date_utc", "2026-08-05"),
        ("base_commit", "424134f7338f610e36d5047d3d334128ae4275e4"),
        ("refresh_state", "STATIC_SOURCE_PIN_MAINTENANCE"),
        ("required_disposition", "KEEP_INCUMBENT"),
        ("execution_state", "NOT_RUN_STATIC_ONLY"),
    ] {
        if refresh.get(key).and_then(Value::as_str) != Some(expected) {
            return Err(format!("post-A3 refresh {key} must be {expected}"));
        }
    }
    if refresh.get("source_pin_path_count").and_then(Value::as_u64) != Some(16)
        || refresh.get("stale_path_count").and_then(Value::as_u64) != Some(1)
        || refresh.get("refreshed_path_count").and_then(Value::as_u64) != Some(1)
    {
        return Err("post-A3 refresh counts drifted".to_owned());
    }
    for key in [
        "source_pin_path_set_changed",
        "historical_a1_revision_changed",
        "historical_a3_claim_revision_changed",
        "a3_keep_decision_changed",
        "dependency_exit_allowed",
    ] {
        if refresh.get(key).and_then(Value::as_bool) != Some(false) {
            return Err(format!("post-A3 refresh {key} must remain false"));
        }
    }

    let rows = array(refresh, "refreshed_paths");
    if rows.len() != 1 {
        return Err("post-A3 refresh must retain one exact path".to_owned());
    }
    let builder = &rows[0];
    if text(builder, "path") != "src/runtime/builder.rs"
        || text(builder, "source_commit") != "24eb7ec6c62e9ba037d70fed4a69c4e733785926"
        || text(builder, "classification") != "PUBLIC_REQUEST_CX_VISIBILITY_AND_DOCUMENTATION_ONLY"
        || text(builder, "previous_sha256")
            != "69e52f8b761944edf5fa038ed3b122ecf9a58da05f5ad15f20d1f8e3e1f8adb1"
        || builder.get("previous_line_count").and_then(Value::as_u64) != Some(8393)
        || text(builder, "current_sha256")
            != "ced1fd3901169475f1e390324aa11458f97f52288e8d54bd6f9e91cc0ca3570c"
        || builder.get("current_line_count").and_then(Value::as_u64) != Some(8398)
        || builder.get("added_line_count").and_then(Value::as_u64) != Some(6)
        || builder.get("deleted_line_count").and_then(Value::as_u64) != Some(1)
        || builder
            .get("toml_entry_points_changed")
            .and_then(Value::as_bool)
            != Some(false)
        || builder
            .get("accepted_toml_contract_changed")
            .and_then(Value::as_bool)
            != Some(false)
    {
        return Err("post-A3 RuntimeBuilder provenance drifted".to_owned());
    }

    let source = read_repo_file("src/runtime/builder.rs");
    let projection = source
        .lines()
        .filter(|line| {
            line.contains("from_toml") || line.contains("to_toml") || line.contains("toml::")
        })
        .collect::<Vec<_>>()
        .join("\n");
    let projection_sha256 = hex::encode(Sha256::digest(projection.as_bytes()));
    if text(builder, "unchanged_toml_token_projection_sha256") != projection_sha256.as_str() {
        return Err("post-A3 TOML token projection drifted".to_owned());
    }
    if !text(refresh, "no_claim_boundary").contains("does not rerun A1 or A3")
        || !text(refresh, "no_claim_boundary").contains("change accepted TOML behavior")
        || !text(refresh, "no_claim_boundary").contains("dependency exit")
    {
        return Err("post-A3 refresh no-claim boundary is incomplete".to_owned());
    }
    Ok(())
}

fn validate_a2_implementation_receipt(inventory: &Value) -> Result<(), String> {
    let a2 = inventory
        .get("a2_implementation_receipt")
        .ok_or_else(|| "a2_implementation_receipt must be present".to_owned())?;
    if !a2.is_object() {
        return Err("a2_implementation_receipt must be an object".to_owned());
    }
    for (key, expected) in [
        ("bead_id", A2_BEAD_ID),
        ("capability_id", CAPABILITY_ID),
        ("captured_date_utc", "2026-08-06"),
        ("implementation_state", "SOURCE_IMPLEMENTED_NOT_EXECUTED"),
        ("execution_state", "NOT_RUN_STATIC_ONLY"),
    ] {
        if a2.get(key).and_then(Value::as_str) != Some(expected) {
            return Err(format!(
                "a2_implementation_receipt.{key} must be {expected}"
            ));
        }
    }

    let expected_commits: BTreeSet<String> = ["cbe4a452a", "0fb5fadc6", "c05c8cb6d"]
        .into_iter()
        .map(str::to_owned)
        .collect();
    let source_commits = array(a2, "source_commits");
    if source_commits.len() != 3
        || row_ids(source_commits, "commit") != expected_commits
        || source_commits
            .iter()
            .any(|row| text(row, "scope").trim().is_empty())
    {
        return Err("A2 must pin its exact three source commits and scopes".to_owned());
    }

    let expected_family_ids: BTreeSet<String> = [
        "CFG-A2-RUNTIME",
        "CFG-A2-ATP-COMMAND",
        "CFG-A2-ATP-INSTALL",
        "CFG-A2-ATPD",
        "CFG-A2-DEPENDENCY-LEDGER",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect();
    let expected_surface_ids: BTreeSet<String> = [
        "CFG-TOML-RUNTIME",
        "CFG-TOML-ATP-COMMAND",
        "CFG-TOML-ATP-INSTALL",
        "CFG-TOML-ATPD",
        "CFG-TOML-DEPENDENCY-LEDGER",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect();
    let families = array(a2, "family_rows");
    if families.len() != 5 || row_ids(families, "family_id") != expected_family_ids {
        return Err("A2 must classify the exact five inventoried config families".to_owned());
    }
    let actual_surface_ids: BTreeSet<String> = families
        .iter()
        .flat_map(|row| {
            array(row, "surface_ids")
                .iter()
                .map(|surface| surface.as_str().expect("surface id").to_owned())
        })
        .collect();
    let classified_surface_count = families
        .iter()
        .map(|row| array(row, "surface_ids").len())
        .sum::<usize>();
    if actual_surface_ids != expected_surface_ids || classified_surface_count != 5 {
        return Err("A2 family rows must cover every inventoried TOML surface once".to_owned());
    }
    for family_id in [
        "CFG-A2-RUNTIME",
        "CFG-A2-ATP-COMMAND",
        "CFG-A2-ATP-INSTALL",
        "CFG-A2-ATPD",
    ] {
        let row = find_row(families, "family_id", family_id);
        if text(row, "family_state") != "SOURCE_IMPLEMENTED_NOT_EXECUTED"
            || text(row, "typed_model").trim().is_empty()
            || array(row, "toml_entry_points").is_empty()
            || array(row, "json_entry_points").is_empty()
            || row.get("precedence_changed").and_then(Value::as_bool) != Some(false)
            || row.get("physical_writer_changed").and_then(Value::as_bool) != Some(false)
        {
            return Err(format!("{family_id} implementation boundary drifted"));
        }
    }
    let ledger = find_row(families, "family_id", "CFG-A2-DEPENDENCY-LEDGER");
    if text(ledger, "family_state") != "EXPLICIT_GENERIC_MANIFEST_TRANSFORM_NOT_APPLICATION_CONFIG"
        || !array(ledger, "json_entry_points").is_empty()
        || ledger.get("precedence_changed").and_then(Value::as_bool) != Some(false)
        || ledger
            .get("physical_writer_changed")
            .and_then(Value::as_bool)
            != Some(false)
    {
        return Err("generic Cargo-manifest transformation must remain explicit".to_owned());
    }

    let canonical = object(a2, "canonical_contract");
    let expected_envelope_fields: BTreeSet<String> = ["config", "schema_version"]
        .into_iter()
        .map(str::to_owned)
        .collect();
    if string_set(
        a2.get("canonical_contract").expect("canonical contract"),
        "envelope_fields",
    ) != expected_envelope_fields
        || canonical
            .get("current_schema_version")
            .and_then(Value::as_u64)
            != Some(1)
    {
        return Err("A2 canonical envelope or schema version drifted".to_owned());
    }
    for (key, expected) in [
        ("missing_schema_version", "MIGRATE_TO_V1"),
        ("unsupported_explicit_schema", "REJECT_READ_AND_WRITE"),
        ("object_key_order", "RECURSIVE_LEXICOGRAPHIC"),
        ("array_order", "PRESERVE_TYPED_ORDER"),
        ("whitespace", "COMPACT"),
        ("finite_number_encoding", "SERDE_JSON_STABLE_SHORTEST"),
        ("nonfinite_number_policy", "REJECT_MODEL_CONVERSION"),
        (
            "path_policy",
            "EXACT_LEXICAL_UTF8_WITHOUT_NORMALIZE_RESOLVE_OR_ACCESS",
        ),
        (
            "unknown_field_policy",
            "RETAIN_SERDE_IGNORE_ON_INPUT_COMPATIBILITY",
        ),
        (
            "required_field_policy",
            "RETAIN_EACH_EXISTING_TYPED_MODEL_REQUIREMENTS",
        ),
    ] {
        if canonical.get(key).and_then(Value::as_str) != Some(expected) {
            return Err(format!("A2 canonical contract {key} must be {expected}"));
        }
    }

    let publication = object(a2, "model_publication_contract");
    for key in [
        "parse_then_validate_before_runtime_mutation",
        "failed_runtime_layer_leaves_fresh_builder_unpublished",
        "canonical_conversion_performs_no_file_io",
    ] {
        if publication.get(key).and_then(Value::as_bool) != Some(true) {
            return Err(format!("A2 model publication contract {key} must be true"));
        }
    }
    if publication
        .get("physical_atomic_write_changed")
        .and_then(Value::as_bool)
        != Some(false)
        || publication
            .get("physical_io_and_diagnostics_owner")
            .and_then(Value::as_str)
            != Some("asupersync-5z2scg.4.4")
        || publication
            .get("real_user_journey_owner")
            .and_then(Value::as_str)
            != Some(A5_BEAD_ID)
    {
        return Err("A2 must retain its A4/A5 ownership boundaries".to_owned());
    }

    let expected_secret_families: BTreeSet<String> = [
        "CFG-A2-RUNTIME",
        "CFG-A2-ATP-COMMAND",
        "CFG-A2-ATP-INSTALL",
        "CFG-A2-ATPD",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect();
    let secret_rows = array(a2, "secret_rows");
    if secret_rows.len() != 4
        || row_ids(secret_rows, "family_id") != expected_secret_families
        || secret_rows
            .iter()
            .any(|row| text(row, "secret_contract").trim().is_empty())
    {
        return Err("A2 must classify every typed family's secret boundary".to_owned());
    }
    let atpd_secret = find_row(secret_rows, "family_id", "CFG-A2-ATPD");
    if text(atpd_secret, "secret_contract")
        != "RQ_AUTH_KEY_REDACTED_BY_SERDE_AND_DEBUG_AND_REDACTION_SENTINEL_REJECTED_ON_JSON_LOAD"
    {
        return Err("A2 atpd secret boundary drifted".to_owned());
    }

    let reconciliation_value = a2
        .get("source_pin_reconciliation")
        .expect("A2 source pin reconciliation");
    let reconciliation = object(a2, "source_pin_reconciliation");
    if reconciliation
        .get("comparison_revision")
        .and_then(Value::as_str)
        != Some("424134f7338f610e36d5047d3d334128ae4275e4")
        || reconciliation
            .get("current_source_commit")
            .and_then(Value::as_str)
            != Some("c05c8cb6d")
        || reconciliation
            .get("top_level_source_pin_count")
            .and_then(Value::as_u64)
            != Some(16)
        || reconciliation
            .get("refreshed_path_count")
            .and_then(Value::as_u64)
            != Some(7)
        || reconciliation
            .get("a2_owned_path_count")
            .and_then(Value::as_u64)
            != Some(6)
        || reconciliation
            .get("unrelated_path_count")
            .and_then(Value::as_u64)
            != Some(1)
    {
        return Err("A2 source-pin reconciliation counts drifted".to_owned());
    }
    let expected_refreshed_paths: BTreeSet<String> = [
        "src/config.rs",
        "src/runtime/env_config.rs",
        "src/runtime/builder.rs",
        "src/cli/atp_config.rs",
        "src/cli/atp_command_tree.rs",
        "src/bin/atpd.rs",
        "tests/fixtures/dependency-capability-baseline-consumer/src/lib.rs",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect();
    let reconciliation_rows = array(reconciliation_value, "rows");
    if reconciliation_rows.len() != 7
        || row_ids(reconciliation_rows, "path") != expected_refreshed_paths
    {
        return Err("A2 must reconcile the exact seven changed source pins".to_owned());
    }
    let top_level_pins = array(inventory, "source_pins");
    let maintenance_value = reconciliation_value
        .get("format_only_maintenance")
        .expect("A2 formatting-only maintenance receipt");
    let maintenance = object(reconciliation_value, "format_only_maintenance");
    if text(maintenance_value, "commit") != "8d94b8b9e4361863599db9a17f7badd4179b2609"
        || text(maintenance_value, "classification")
            != "FORMAT_ONLY_RUSTFMT_NO_CONFIG_CONTRACT_CHANGE"
        || maintenance
            .get("refreshed_path_count")
            .and_then(Value::as_u64)
            != Some(4)
        || maintenance
            .get("accepted_toml_input_changed")
            .and_then(Value::as_bool)
            != Some(false)
    {
        return Err("A2 format-only source-pin maintenance receipt drifted".to_owned());
    }
    let maintenance_rows = array(maintenance_value, "rows");
    let expected_maintenance_paths: BTreeSet<String> = [
        "src/config.rs",
        "src/runtime/env_config.rs",
        "src/cli/atp_config.rs",
        "src/bin/atpd.rs",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect();
    if maintenance_rows.len() != 4
        || row_ids(maintenance_rows, "path") != expected_maintenance_paths
    {
        return Err("A2 must reconcile the exact four formatting-only pin drifts".to_owned());
    }
    for (path, previous_sha256, previous_line_count) in [
        (
            "src/config.rs",
            "8315e1e2d4b0fe2223356d364c2656f2f6d4b93ca71b705a7b328ee41cb3f05e",
            2164,
        ),
        (
            "src/runtime/env_config.rs",
            "84222f9f0f62163c47947ae7805a275c4192ffa712c6fff83c3035acae65ff90",
            1170,
        ),
        (
            "src/cli/atp_config.rs",
            "9bb110bceb286d9dfbce19657a09b239c08de71641b5517fb3f699f35bc2ec2f",
            1016,
        ),
        (
            "src/bin/atpd.rs",
            "aa1ff63fbd19e4252171c66fb6c02aeb8358a3c100ae73b2169db2399ee857c9",
            2664,
        ),
    ] {
        let row = find_row(maintenance_rows, "path", path);
        let pin = find_row(top_level_pins, "path", path);
        if text(row, "previous_sha256") != previous_sha256
            || row.get("previous_line_count").and_then(Value::as_u64) != Some(previous_line_count)
            || text(row, "current_sha256") != text(pin, "sha256")
            || row.get("current_line_count").and_then(Value::as_u64)
                != pin.get("line_count").and_then(Value::as_u64)
        {
            return Err(format!(
                "A2 formatting-only maintenance row for {path} drifted"
            ));
        }
    }
    for row in reconciliation_rows {
        let path = text(row, "path");
        let pin = find_row(top_level_pins, "path", path);
        if text(row, "source_commit").trim().is_empty()
            || text(row, "classification").trim().is_empty()
            || text(row, "previous_sha256").trim().is_empty()
            || text(row, "current_sha256") != text(pin, "sha256")
            || row.get("current_line_count").and_then(Value::as_u64)
                != pin.get("line_count").and_then(Value::as_u64)
            || row
                .get("accepted_toml_input_changed")
                .and_then(Value::as_bool)
                != Some(false)
        {
            return Err(format!("A2 reconciliation row for {path} drifted"));
        }
    }
    let unrelated = find_row(
        reconciliation_rows,
        "path",
        "tests/fixtures/dependency-capability-baseline-consumer/src/lib.rs",
    );
    if text(unrelated, "classification") != "UNRELATED_DOWNSTREAM_STREAM_AND_ATP_CONTRACT_GROWTH" {
        return Err("A2 must separate unrelated downstream fixture growth".to_owned());
    }

    let expected_tests: BTreeSet<String> = [
        "versioned_config_document_has_recursive_canonical_golden",
        "versioned_config_document_migrates_missing_v1_and_ignores_unknown_fields",
        "versioned_config_document_rejects_unsupported_schema_on_read_and_write",
        "toml_and_json_share_one_typed_layer_with_canonical_golden",
        "empty_toml_and_empty_json_payload_share_defaults",
        "json_missing_version_migrates_and_unknown_fields_stay_ignored",
        "json_rejects_unsupported_schema_and_wrong_field_type",
        "json_file_uses_the_same_capability_mediated_read_path",
        "from_json_str_builds_runtime_through_the_shared_typed_layer",
        "from_json_str_rejects_unsupported_schema_version",
        "precedence_programmatic_over_env_over_json",
        "atp_command_toml_and_json_share_one_model_and_exact_golden",
        "atp_command_empty_unknown_schema_and_nonfinite_rules_are_explicit",
        "atp_install_toml_and_json_share_one_model_and_exact_golden",
        "atp_install_outer_schema_is_additive_but_payload_requirements_remain",
        "atp_install_canonical_paths_require_utf8_without_normalizing",
        "atpd_toml_and_json_share_one_model_and_exact_golden",
        "atpd_json_schema_unknown_and_required_field_rules_are_additive",
        "atpd_secret_is_redacted_from_debug_serde_and_canonical_output",
        "atpd_loader_selects_json_additively_and_retains_toml",
        "atpd_canonical_paths_require_utf8_without_normalizing",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect();
    if string_set(a2, "source_test_cases") != expected_tests {
        return Err("A2 must retain the exact twenty-one source test cases".to_owned());
    }
    let source = [
        "src/config.rs",
        "src/runtime/env_config.rs",
        "src/runtime/builder.rs",
        "src/cli/atp_config.rs",
        "src/cli/atp_command_tree.rs",
        "src/bin/atpd.rs",
    ]
    .into_iter()
    .map(read_repo_file)
    .collect::<Vec<_>>()
    .join("\n");
    for test_name in &expected_tests {
        let declaration = format!("fn {test_name}(");
        if !source.contains(declaration.as_str()) {
            return Err(format!("A2 source test {test_name} is missing"));
        }
    }
    if array(a2, "open_obligations").len() != 3
        || !text(a2, "no_claim_boundary").contains("does not claim compilation")
        || !text(a2, "no_claim_boundary").contains("physical atomic writes")
        || !text(a2, "no_claim_boundary").contains("permission to remove")
    {
        return Err("A2 must retain open obligations and a complete no-claim boundary".to_owned());
    }
    Ok(())
}

fn validate_inventory(inventory: &Value) -> Result<(), String> {
    if inventory.get("schema_version").and_then(Value::as_u64) != Some(1) {
        return Err("schema_version must be 1".to_owned());
    }
    for (key, expected) in [
        ("artifact_id", "config-toml-capability-inventory-v1"),
        ("program_id", PROGRAM_ID),
        ("bead_id", BEAD_ID),
        ("capability_id", CAPABILITY_ID),
        ("baseline_revision", BASELINE_REVISION),
        ("authority_revision", AUTHORITY_REVISION),
    ] {
        if inventory.get(key).and_then(Value::as_str) != Some(expected) {
            return Err(format!("{key} must be {expected}"));
        }
    }

    let authority = object(inventory, "authority");
    for (key, expected) in [
        ("adr_id", ADR_ID),
        ("decision", "ADDITIVE_COEXISTENCE"),
        ("disposition", "KEEP_UNTIL_PARITY"),
        ("cutover_state", "KEEP_INCUMBENT"),
    ] {
        if authority.get(key).and_then(Value::as_str) != Some(expected) {
            return Err(format!("authority.{key} must be {expected}"));
        }
    }
    if authority
        .get("dependency_exit_allowed")
        .and_then(Value::as_bool)
        != Some(false)
    {
        return Err("authority must forbid dependency exit".to_owned());
    }

    let policy = object(inventory, "policy");
    if policy.get("zero_unknown_required").and_then(Value::as_bool) != Some(true)
        || policy.get("unknown_rows").and_then(Value::as_u64) != Some(0)
    {
        return Err("policy must require and report zero unknown rows".to_owned());
    }
    for key in ["allowed_inventory_states", "allowed_evidence_states"] {
        if string_set(inventory.get("policy").expect("policy"), key).contains("UNKNOWN") {
            return Err(format!("{key} must not permit UNKNOWN"));
        }
    }
    validate_state_fields(inventory, "$")?;

    let expected_profiles: BTreeSet<String> = [
        "CFG-PROFILE-DEFAULT",
        "CFG-PROFILE-CONFIG-FILE",
        "CFG-PROFILE-CLI",
        "CFG-PROFILE-ATPD",
        "CFG-PROFILE-DEPENDENCY-LEDGER",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect();
    if row_ids(array(inventory, "feature_profiles"), "profile_id") != expected_profiles {
        return Err("feature profiles must cover the exact five live build profiles".to_owned());
    }

    let expected_surfaces: BTreeSet<String> = [
        "CFG-TOML-RUNTIME",
        "CFG-TOML-ATP-COMMAND",
        "CFG-TOML-ATP-INSTALL",
        "CFG-TOML-ATPD",
        "CFG-TOML-DEPENDENCY-LEDGER",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect();
    let surfaces = array(inventory, "toml_surfaces");
    if row_ids(surfaces, "surface_id") != expected_surfaces {
        return Err("production/internal TOML surface inventory drifted".to_owned());
    }
    for (surface_id, field_count) in [
        ("CFG-TOML-RUNTIME", 14),
        ("CFG-TOML-ATP-COMMAND", 11),
        ("CFG-TOML-ATP-INSTALL", 14),
        ("CFG-TOML-ATPD", 45),
        ("CFG-TOML-DEPENDENCY-LEDGER", 0),
    ] {
        let row = find_row(surfaces, "surface_id", surface_id);
        if row.get("field_count").and_then(Value::as_u64) != Some(field_count) {
            return Err(format!(
                "{surface_id} field count must remain {field_count}"
            ));
        }
        let enumerated = array(row, "field_groups")
            .iter()
            .map(|group| array(group, "fields").len())
            .sum::<usize>();
        if enumerated != field_count as usize {
            return Err(format!(
                "{surface_id} enumerates {enumerated} fields, expected {field_count}"
            ));
        }
    }

    let expected_adjacent: BTreeSet<String> = [
        "CFG-TOML-FRANKEN-DECISION-TEST",
        "CFG-TOML-MOCK-METAMORPHIC",
        "CFG-NON-TOML-RAPTORQ",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect();
    if row_ids(array(inventory, "adjacent_surfaces"), "surface_id") != expected_adjacent {
        return Err("adjacent test-only and non-TOML surface inventory drifted".to_owned());
    }

    let grammar = array(inventory, "grammar_constructs");
    if grammar.len() != 16 || row_ids(grammar, "construct_id").len() != 16 {
        return Err("grammar inventory must contain sixteen unique constructs".to_owned());
    }
    let precedence = array(inventory, "precedence_contracts");
    if row_ids(precedence, "precedence_id")
        != surfaces
            .iter()
            .map(|row| text(row, "precedence_id").to_owned())
            .collect()
    {
        return Err("every TOML surface must route to one precedence contract".to_owned());
    }

    let errors = array(inventory, "error_contracts");
    if errors.len() != 12 || row_ids(errors, "error_id").len() != 12 {
        return Err("error inventory must contain twelve unique distinctions".to_owned());
    }
    for row in surfaces {
        for error_id in array(row, "error_contract_ids") {
            let error_id = error_id
                .as_str()
                .ok_or_else(|| "surface error ids must be strings".to_owned())?;
            if !errors.iter().any(|candidate| {
                candidate.get("error_id").and_then(Value::as_str) == Some(error_id)
            }) {
                return Err(format!(
                    "{} references missing {error_id}",
                    text(row, "surface_id")
                ));
            }
        }
    }

    let corpus = array(inventory, "corpus_cases");
    if corpus.len() != 27 || row_ids(corpus, "case_id").len() != 27 {
        return Err("corpus must contain twenty-seven unique cases".to_owned());
    }
    let required_classes: BTreeSet<String> = [
        "empty",
        "valid-scalars",
        "valid-collections",
        "valid-comments-formatting",
        "malformed-duplicate",
        "malformed-conflict",
        "malformed-syntax",
        "generic-value-boundary",
        "valid-all-fields",
        "unknown-security-adjacent",
        "malformed-type",
        "semantic-error",
        "valid-boundary",
        "unknown-field",
        "malformed-enum",
        "programmatic-precedence-boundary",
        "valid-write-read",
        "path-security-error",
        "missing-file",
        "unknown-security-field",
        "valid-cargo-manifest-shapes",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect();
    let actual_classes: BTreeSet<String> = corpus
        .iter()
        .map(|row| text(row, "class").to_owned())
        .collect();
    if !required_classes.is_subset(&actual_classes) {
        return Err("corpus is missing a required happy, boundary, or error class".to_owned());
    }

    let expected_children: BTreeSet<String> = (1..=5)
        .map(|suffix| format!("asupersync-5z2scg.4.{suffix}"))
        .collect();
    let children = array(inventory, "child_capability_rows");
    if row_ids(children, "owner_bead") != expected_children {
        return Err("every CFG A1-A5 child must own exactly one row".to_owned());
    }
    for row in children {
        if array(row, "required_evidence").is_empty() || text(row, "no_claim").trim().is_empty() {
            return Err(format!(
                "{} must name evidence and a no-claim boundary",
                text(row, "owner_bead")
            ));
        }
    }
    let a3_child = find_row(children, "owner_bead", A3_BEAD_ID);
    if text(a3_child, "evidence_state") != "SOURCE_BASELINED" {
        return Err("CFG A3 child must record the source-baselined KEEP decision".to_owned());
    }
    let a2_child = find_row(children, "owner_bead", A2_BEAD_ID);
    if text(a2_child, "evidence_state") != "SOURCE_IMPLEMENTED_NOT_EXECUTED" {
        return Err("CFG A2 child must retain its fail-closed source-only state".to_owned());
    }

    validate_a2_implementation_receipt(inventory)?;

    let a3 = inventory
        .get("a3_keep_receipt")
        .ok_or_else(|| "a3_keep_receipt must be present".to_owned())?;
    if !a3.is_object() {
        return Err("a3_keep_receipt must be an object".to_owned());
    }
    for (key, expected) in [
        ("bead_id", A3_BEAD_ID),
        ("capability_id", CAPABILITY_ID),
        ("decision", "KEEP_INCUMBENT"),
        ("decision_state", "EVIDENCE_BACKED_KEEP"),
        ("terminal_cutover_owner", A5_BEAD_ID),
        (
            "verification_state",
            "STATIC_DECISION_AUTHORED_NOT_EXECUTED",
        ),
    ] {
        if a3.get(key).and_then(Value::as_str) != Some(expected) {
            return Err(format!("a3_keep_receipt.{key} must be {expected}"));
        }
    }
    for key in [
        "replacement_selected",
        "owned_parser_present",
        "owned_writer_present",
        "dependency_exit_allowed",
        "terminal_cutover_allowed",
    ] {
        if a3.get(key).and_then(Value::as_bool) != Some(false) {
            return Err(format!("a3_keep_receipt.{key} must remain false"));
        }
    }
    if a3
        .get("all_currently_accepted_documents_preserved")
        .and_then(Value::as_bool)
        != Some(true)
    {
        return Err("A3 KEEP must preserve every currently accepted document".to_owned());
    }

    let preservation_scope = a3
        .get("preservation_scope")
        .ok_or_else(|| "A3 preservation_scope must be present".to_owned())?;
    if !preservation_scope.is_object() {
        return Err("A3 preservation_scope must be an object".to_owned());
    }
    if string_set(preservation_scope, "surface_ids") != expected_surfaces {
        return Err("A3 KEEP must preserve every inventoried TOML surface".to_owned());
    }
    if string_set(preservation_scope, "grammar_construct_ids") != row_ids(grammar, "construct_id") {
        return Err("A3 KEEP must preserve every observed grammar construct".to_owned());
    }
    if string_set(preservation_scope, "error_contract_ids") != row_ids(errors, "error_id") {
        return Err("A3 KEEP must preserve every error distinction".to_owned());
    }
    if preservation_scope
        .get("corpus_case_count")
        .and_then(Value::as_u64)
        != Some(corpus.len() as u64)
    {
        return Err("A3 KEEP must preserve the complete corpus".to_owned());
    }

    let source_reconciliation = a3
        .get("claim_source_reconciliation")
        .ok_or_else(|| "A3 claim source reconciliation must be present".to_owned())?;
    if source_reconciliation
        .get("source_pin_count")
        .and_then(Value::as_u64)
        != Some(array(inventory, "source_pins").len() as u64)
        || source_reconciliation
            .get("drifted_source_pin_count")
            .and_then(Value::as_u64)
            != Some(4)
        || source_reconciliation
            .get("conclusion")
            .and_then(Value::as_str)
            != Some("NO_ACCEPTED_TOML_PARSER_OR_WRITER_CONTRACT_CHANGE_DETECTED")
    {
        return Err("A3 source reconciliation counts or conclusion drifted".to_owned());
    }
    let reconciliation_rows = array(source_reconciliation, "rows");
    let expected_drifted_paths: BTreeSet<String> = [
        "Cargo.toml",
        "src/runtime/builder.rs",
        "src/bin/dependency_marginal_ledger.rs",
        "tests/fixtures/dependency-capability-baseline-consumer/src/lib.rs",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect();
    if reconciliation_rows.len() != expected_drifted_paths.len()
        || row_ids(reconciliation_rows, "path") != expected_drifted_paths
        || reconciliation_rows
            .iter()
            .any(|row| text(row, "toml_contract_effect").trim().is_empty())
    {
        return Err("A3 must classify each claim-time source-pin drift exactly once".to_owned());
    }

    let expected_a3_gaps: BTreeSet<String> =
        ["CFG-GAP-02", "CFG-GAP-06", "CFG-GAP-10", "CFG-GAP-12"]
            .into_iter()
            .map(str::to_owned)
            .collect();
    if string_set(a3, "blocking_gap_ids") != expected_a3_gaps {
        return Err("A3 KEEP must retain its exact four blocking gaps".to_owned());
    }

    let expected_replacement_rows: BTreeSet<String> = [
        "CFG-A3-REPLACE-PARSER",
        "CFG-A3-REPLACE-WRITER",
        "CFG-A3-REPLACE-BOUNDS",
        "CFG-A3-REPLACE-INDEPENDENT",
        "CFG-A3-REPLACE-GENERATIVE",
        "CFG-A3-REPLACE-DIAGNOSTICS",
        "CFG-A3-REPLACE-CONSUMERS",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect();
    let replacement_rows = array(a3, "replacement_evidence_rows");
    if replacement_rows.len() != expected_replacement_rows.len()
        || row_ids(replacement_rows, "evidence_id") != expected_replacement_rows
        || replacement_rows
            .iter()
            .any(|row| text(row, "state") != "NOT_PRESENT")
    {
        return Err("A3 replacement evidence must remain explicitly absent under KEEP".to_owned());
    }
    if array(a3, "revisit_conditions").len() != 3 || text(a3, "no_claim_boundary").trim().is_empty()
    {
        return Err("A3 KEEP must retain revisit conditions and a no-claim boundary".to_owned());
    }

    let expected_gaps: BTreeSet<String> = [1_u8, 2, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17]
        .into_iter()
        .map(|suffix| format!("CFG-GAP-{suffix:02}"))
        .collect();
    let gaps = array(inventory, "known_gaps");
    if row_ids(gaps, "gap_id") != expected_gaps {
        return Err("known config gaps must retain the exact routed set".to_owned());
    }
    for row in gaps {
        if text(row, "owner_bead").is_empty() || text(row, "evidence_state") != "BLOCKED_GAP" {
            return Err(format!(
                "{} must be routed and fail closed",
                text(row, "gap_id")
            ));
        }
    }
    for gap_id in expected_a3_gaps {
        let gap = find_row(gaps, "gap_id", &gap_id);
        if text(gap, "owner_bead") != A3_BEAD_ID {
            return Err(format!("{gap_id} must remain owned by CFG A3"));
        }
    }

    let consumers = array(inventory, "downstream_files_and_consumers");
    if consumers.len() != 7 || row_ids(consumers, "consumer_id").len() != 7 {
        return Err("downstream inventory must contain seven unique consumers".to_owned());
    }
    if text(inventory, "no_claim_boundary").trim().is_empty() {
        return Err("top-level no-claim boundary is required".to_owned());
    }
    validate_post_a3_provenance_refresh(inventory)?;
    Ok(())
}

#[test]
fn inventory_is_complete_source_pinned_and_zero_unknown() {
    let inventory = artifact();
    validate_inventory(&inventory).unwrap_or_else(|error| panic!("{error}"));

    for pin in array(&inventory, "source_pins") {
        let path = text(pin, "path");
        let bytes = read_repo_bytes(path);
        let digest = hex::encode(Sha256::digest(&bytes));
        assert_eq!(digest, text(pin, "sha256"), "{path} source pin drifted");
        let line_count = read_repo_file(path).lines().count() as u64;
        assert_eq!(
            Some(line_count),
            pin.get("line_count").and_then(Value::as_u64),
            "{path} line count drifted"
        );
    }
}

#[test]
fn authority_registry_and_live_source_routes_are_truthful() {
    let inventory = artifact();
    let adr = read_repo_file(ADR_PATH);
    for marker in [
        "ADDITIVE_COEXISTENCE",
        "KEEP_UNTIL_PARITY",
        "KEEP_INCUMBENT",
        "CFG-GAP-01",
        "src/runtime/env_config.rs",
        "src/cli/atp_config.rs",
        "src/bin/atpd.rs",
        "src/bin/dependency_marginal_ledger.rs",
    ] {
        assert!(adr.contains(marker), "ADR must retain {marker}");
    }

    let registry = parse_repo_json(CAPABILITY_REGISTRY_PATH);
    let capability = array(&registry, "capabilities")
        .iter()
        .find(|row| row.get("capability_id").and_then(Value::as_str) == Some(CAPABILITY_ID))
        .expect("capability registry must retain CAP-CONFIG-TOML-JSON");
    assert_eq!(
        capability.get("cutover_state").and_then(Value::as_str),
        Some("KEEP_INCUMBENT")
    );
    assert_eq!(
        capability.get("disposition").and_then(Value::as_str),
        Some("KEEP_UNTIL_PARITY")
    );
    let stale_owners = string_set(capability, "source_owners");
    assert_eq!(
        stale_owners,
        ["src/bin/asupersync.rs", "src/config.rs"]
            .into_iter()
            .map(str::to_owned)
            .collect(),
        "CFG-GAP-01 must stay truthful until the registry owner repairs it"
    );

    let api_map = read_repo_file(API_SURFACE_MAP_PATH);
    assert!(api_map.contains("\"name\": \"config::ConfigLoader\""));
    assert!(api_map.contains("\"symbol\": \"runtime::RuntimeBuilder\""));

    let runtime = read_repo_file("src/runtime/env_config.rs");
    let builder = read_repo_file("src/runtime/builder.rs");
    let atp = read_repo_file("src/cli/atp_config.rs");
    let atpd = read_repo_file("src/bin/atpd.rs");
    let ledger = read_repo_file("src/bin/dependency_marginal_ledger.rs");
    let non_toml = read_repo_file("src/config.rs");
    assert!(runtime.contains("toml::from_str"));
    assert!(builder.contains("pub fn from_toml("));
    assert!(builder.contains("pub fn from_toml_str("));
    assert!(atp.contains("toml::from_str"));
    assert!(atp.contains("toml::to_string_pretty"));
    assert!(atpd.contains("let config: AtpdConfig = toml::from_str"));
    assert!(ledger.contains("toml::Value"));
    assert!(ledger.contains("toml::to_string_pretty"));
    assert!(
        !non_toml.contains("toml::"),
        "src/config.rs must remain explicitly classified as non-TOML"
    );
    assert!(non_toml.contains("pub struct VersionedConfigDocument<T>"));
    assert!(non_toml.contains("pub fn to_canonical_json<T>"));
    assert!(runtime.contains("pub struct RuntimeConfigLayer"));
    assert!(runtime.contains("pub fn parse_json_str"));
    assert!(runtime.contains("pub fn runtime_config_to_canonical_json"));
    assert!(builder.contains("pub fn from_json("));
    assert!(builder.contains("pub fn from_json_str("));
    assert!(atp.contains("pub fn parse_atp_command_json"));
    assert!(atp.contains("pub fn atp_command_to_canonical_json"));
    assert!(atp.contains("pub fn to_canonical_json(&self)"));
    assert!(atpd.contains("pub fn to_redacted_canonical_json(&self)"));
    assert!(atpd.contains("serialize_redacted_rq_auth_key"));
    assert!(atpd.contains("extension.eq_ignore_ascii_case(\"json\")"));

    let surface_paths: BTreeSet<String> = array(&inventory, "toml_surfaces")
        .iter()
        .flat_map(|row| {
            array(row, "source_paths")
                .iter()
                .map(|path| path.as_str().expect("source path").to_owned())
        })
        .collect();
    for expected in [
        "src/runtime/env_config.rs",
        "src/runtime/builder.rs",
        "src/cli/atp_config.rs",
        "src/cli/atp_command_tree.rs",
        "src/cli/first_run.rs",
        "src/cli/upgrade.rs",
        "src/bin/atpd.rs",
        "src/bin/dependency_marginal_ledger.rs",
    ] {
        assert!(
            surface_paths.contains(expected),
            "missing live source owner {expected}"
        );
    }
}

#[test]
fn generic_toml_grammar_corpus_matches_observed_parser_behavior() {
    let inventory = artifact();
    let generic_cases: Vec<&Value> = array(&inventory, "corpus_cases")
        .iter()
        .filter(|row| row.get("surface_id").and_then(Value::as_str) == Some("GENERIC"))
        .collect();
    assert_eq!(generic_cases.len(), 8);
    for row in generic_cases {
        let result = toml::from_str::<toml::Value>(text(row, "document"));
        match text(row, "expected") {
            "ACCEPT" => assert!(
                result.is_ok(),
                "{} unexpectedly rejected: {:?}",
                text(row, "case_id"),
                result.err()
            ),
            "REJECT" => assert!(
                result.is_err(),
                "{} unexpectedly accepted",
                text(row, "case_id")
            ),
            expected => panic!("unhandled generic expectation {expected}"),
        }
    }

    let commented = "# leading\nkey = \"value\" # trailing\n";
    let parsed: toml::Value = toml::from_str(commented).expect("comments must parse");
    let rendered = toml::to_string_pretty(&parsed).expect("generic value must serialize");
    assert_eq!(
        parsed.get("key").and_then(toml::Value::as_str),
        Some("value")
    );
    assert!(
        !rendered.contains('#'),
        "pretty writer must not claim comment retention"
    );
}

#[cfg(feature = "config-file")]
#[test]
fn runtime_toml_corpus_preserves_empty_full_unknown_error_and_boundary_cases() {
    use asupersync::runtime::RuntimeBuilder;
    use asupersync::runtime::env_config::parse_toml_str;

    let inventory = artifact();
    let corpus = array(&inventory, "corpus_cases");
    let empty = text(
        find_row(corpus, "case_id", "CFG-CORPUS-RUNTIME-EMPTY"),
        "document",
    );
    let empty_config = parse_toml_str(empty).expect("empty runtime TOML must parse");
    assert!(empty_config.scheduler.worker_threads.is_none());
    assert!(empty_config.blocking.max_threads.is_none());
    RuntimeBuilder::from_toml_str(empty).expect("empty runtime TOML must build an overlay");

    let full = text(
        find_row(corpus, "case_id", "CFG-CORPUS-RUNTIME-FULL"),
        "document",
    );
    let full_config = parse_toml_str(full).expect("full runtime TOML must parse");
    assert_eq!(full_config.scheduler.worker_threads, Some(8));
    assert_eq!(full_config.scheduler.poll_budget, Some(u32::MAX));
    assert_eq!(full_config.scheduler.governor_interval, Some(u32::MAX));
    assert_eq!(
        full_config.scheduler.adaptive_cancel_streak_epoch_steps,
        Some(u32::MAX)
    );
    assert_eq!(full_config.blocking.min_threads, Some(2));
    assert_eq!(full_config.blocking.max_threads, Some(32));
    RuntimeBuilder::from_toml_str(full).expect("full runtime TOML must apply");

    let unknown = text(
        find_row(corpus, "case_id", "CFG-CORPUS-RUNTIME-UNKNOWN"),
        "document",
    );
    let unknown_config = parse_toml_str(unknown).expect("unknown fields are currently ignored");
    assert_eq!(unknown_config.scheduler.worker_threads, Some(2));

    for case_id in [
        "CFG-CORPUS-RUNTIME-WRONG-TYPE",
        "CFG-CORPUS-RUNTIME-NUL-PREFIX",
    ] {
        let document = text(find_row(corpus, "case_id", case_id), "document");
        assert!(
            RuntimeBuilder::from_toml_str(document).is_err(),
            "{case_id} must fail"
        );
    }
}

#[cfg(feature = "cli")]
#[test]
fn atp_typed_toml_corpus_preserves_option_boundaries_roundtrip_and_errors() {
    use asupersync::cli::AtpConfig;
    use asupersync::cli::atp_config::{
        AtpInstallConfig, ConfigVersion, ProofRetentionPolicy, ReceiveSafetyPolicy,
    };
    use semver::Version;

    let inventory = artifact();
    let corpus = array(&inventory, "corpus_cases");

    let empty: AtpConfig = toml::from_str("").expect("empty ATP command layer must parse");
    assert!(empty.profile.is_none());
    assert!(empty.chunk_size.is_none());
    assert!(empty.verbose.is_none());

    let boundary = text(
        find_row(corpus, "case_id", "CFG-CORPUS-ATP-COMMAND-BOUNDARY"),
        "document",
    );
    let boundary: AtpConfig = toml::from_str(boundary).expect("signed TOML max must parse");
    assert_eq!(boundary.chunk_size, Some(i64::MAX as u64));
    assert_eq!(boundary.max_concurrent, Some(u32::MAX));

    let unsigned_max = text(
        find_row(corpus, "case_id", "CFG-CORPUS-ATP-COMMAND-FULL"),
        "document",
    );
    let unsigned_max: AtpConfig =
        toml::from_str(unsigned_max).expect("direct u64 target must accept u64::MAX");
    assert_eq!(unsigned_max.chunk_size, Some(u64::MAX));
    assert_eq!(unsigned_max.timeout, Some(u64::MAX));

    let unknown = text(
        find_row(corpus, "case_id", "CFG-CORPUS-ATP-COMMAND-UNKNOWN"),
        "document",
    );
    let unknown: AtpConfig = toml::from_str(unknown).expect("unknown ATP field is ignored");
    assert!(unknown.profile.is_some());
    assert!(
        toml::from_str::<AtpConfig>(text(
            find_row(corpus, "case_id", "CFG-CORPUS-ATP-COMMAND-BAD-ENUM"),
            "document"
        ))
        .is_err()
    );

    assert!(toml::from_str::<AtpInstallConfig>("").is_err());
    let install = AtpInstallConfig {
        schema_version: ConfigVersion::current(),
        version: Some(Version::parse("1.2.3").expect("valid semver")),
        identity_path: PathBuf::from("/tmp/asupersync/identity.key"),
        inbox_dir: PathBuf::from("/tmp/asupersync/inbox"),
        peer_dir: PathBuf::from("/tmp/asupersync/peers"),
        daemon_state_dir: PathBuf::from("/tmp/asupersync/state"),
        receive_safety_policy: ReceiveSafetyPolicy::KnownPeersOnly,
        proof_retention_policy: ProofRetentionPolicy::Days(30),
        enable_tailscale: true,
        allow_relays: false,
        logging_level: "info".to_owned(),
        service_platform: "linux".to_owned(),
        service_daemon_enabled: true,
        service_auto_start: false,
    };
    let rendered = toml::to_string_pretty(&install).expect("install config must serialize");
    let reparsed: AtpInstallConfig =
        toml::from_str(&rendered).expect("rendered install config must parse");
    assert_eq!(reparsed, install);
    let with_unknown = rendered.replacen(
        "\n[schema_version]",
        "\nfuture_security_mode = \"permissive\"\n\n[schema_version]",
        1,
    );
    let reparsed_unknown: AtpInstallConfig =
        toml::from_str(&with_unknown).expect("unknown install fields are currently ignored");
    assert_eq!(reparsed_unknown, install);
}

#[test]
fn precedence_io_errors_consumers_and_docs_remain_explicit() {
    let inventory = artifact();
    let runtime_precedence = find_row(
        array(&inventory, "precedence_contracts"),
        "precedence_id",
        "CFG-PRECEDENCE-RUNTIME",
    );
    assert_eq!(
        array(runtime_precedence, "low_to_high")
            .iter()
            .map(|entry| entry.as_str().expect("precedence entry"))
            .collect::<Vec<_>>(),
        vec![
            "RuntimeConfig::default",
            "RuntimeBuilder::from_toml or from_toml_str",
            "RuntimeBuilder::with_env_overrides when called after TOML construction",
            "later RuntimeBuilder programmatic setters",
        ]
    );

    let atp = read_repo_file("src/cli/atp_config.rs");
    assert!(atp.contains("self.load_daemon_policy()?;"));
    assert!(atp.contains("self.load_local_config()?;"));
    assert!(!atp.contains("self.load_user_config()?;"));
    assert!(atp.contains("if let Ok(config) = self.load_config_file"));
    assert!(atp.contains("fs::write(&validated_path, content)"));
    assert!(atp.contains("fs::write(path, content)"));

    let atpd = read_repo_file("src/bin/atpd.rs");
    assert!(atpd.contains("load_daemon_config(&cli.config).unwrap_or_else"));
    assert!(atpd.contains("Failed to load config"));
    assert!(atpd.contains("AtpdConfig::default()"));
    assert!(!atpd.contains("deny_unknown_fields"));

    let runtime = read_repo_file("src/runtime/env_config.rs");
    assert!(!runtime.contains("deny_unknown_fields"));
    assert!(runtime.contains("failed to parse TOML config"));
    assert!(runtime.contains("failed to read config file"));

    let doc = read_repo_file(DOC_PATH);
    let begin = doc.find(DOC_BEGIN).expect("doc begin marker");
    let end = doc.find(DOC_END).expect("doc end marker");
    assert!(begin < end);
    for marker in [
        "`CFG-TOML-RUNTIME`",
        "`CFG-TOML-ATP-COMMAND`",
        "`CFG-TOML-ATP-INSTALL`",
        "`CFG-TOML-ATPD`",
        "`CFG-TOML-DEPENDENCY-LEDGER`",
        "`CFG-NON-TOML-RAPTORQ`",
        "`CFG-GAP-16`",
        "zero `UNKNOWN`",
        "A2 additive JSON source implementation",
        "SOURCE_IMPLEMENTED_NOT_EXECUTED",
        "twenty-one focused source tests",
        "model-publication rule",
        "A3 incumbent decision",
        "EVIDENCE_BACKED_KEEP",
        "STATIC_DECISION_AUTHORED_NOT_EXECUTED",
        "request_cx_with_budget",
        "static source-pin maintenance only",
    ] {
        assert!(doc.contains(marker), "documentation must retain {marker}");
    }
}

#[test]
fn fail_closed_mutations_are_rejected() {
    let inventory = artifact();

    let mut dependency_exit = inventory.clone();
    dependency_exit["authority"]["dependency_exit_allowed"] = Value::Bool(true);
    assert!(validate_inventory(&dependency_exit).is_err());

    let mut unknown_state = inventory.clone();
    unknown_state["feature_profiles"][0]["evidence_state"] = Value::String("UNKNOWN".to_owned());
    assert!(validate_inventory(&unknown_state).is_err());

    let mut missing_surface = inventory.clone();
    missing_surface["toml_surfaces"]
        .as_array_mut()
        .expect("surfaces array")
        .pop();
    assert!(validate_inventory(&missing_surface).is_err());

    let mut wrong_field_count = inventory.clone();
    wrong_field_count["toml_surfaces"][0]["field_count"] = Value::from(13_u64);
    assert!(validate_inventory(&wrong_field_count).is_err());

    let mut missing_gap = inventory.clone();
    missing_gap["known_gaps"]
        .as_array_mut()
        .expect("gaps array")
        .pop();
    assert!(validate_inventory(&missing_gap).is_err());

    let mut replace_decision = inventory.clone();
    replace_decision["a3_keep_receipt"]["decision"] = Value::String("REPLACE".to_owned());
    assert!(validate_inventory(&replace_decision).is_err());

    let mut a3_dependency_exit = inventory.clone();
    a3_dependency_exit["a3_keep_receipt"]["dependency_exit_allowed"] = Value::Bool(true);
    assert!(validate_inventory(&a3_dependency_exit).is_err());

    let mut missing_replacement_row = inventory.clone();
    missing_replacement_row["a3_keep_receipt"]["replacement_evidence_rows"]
        .as_array_mut()
        .expect("replacement evidence rows")
        .pop();
    assert!(validate_inventory(&missing_replacement_row).is_err());

    let mut false_green = inventory.clone();
    false_green["a3_keep_receipt"]["replacement_evidence_rows"][0]["state"] =
        Value::String("SAME".to_owned());
    assert!(validate_inventory(&false_green).is_err());

    let mut wrong_cutover_owner = inventory.clone();
    wrong_cutover_owner["a3_keep_receipt"]["terminal_cutover_owner"] =
        Value::String(A3_BEAD_ID.to_owned());
    assert!(validate_inventory(&wrong_cutover_owner).is_err());

    let mut false_a2_execution = inventory.clone();
    false_a2_execution["a2_implementation_receipt"]["execution_state"] =
        Value::String("EXECUTED".to_owned());
    assert!(validate_inventory(&false_a2_execution).is_err());

    let mut missing_a2_family = inventory.clone();
    missing_a2_family["a2_implementation_receipt"]["family_rows"]
        .as_array_mut()
        .expect("A2 family rows")
        .pop();
    assert!(validate_inventory(&missing_a2_family).is_err());

    let mut changed_a2_precedence = inventory.clone();
    changed_a2_precedence["a2_implementation_receipt"]["family_rows"][0]["precedence_changed"] =
        Value::Bool(true);
    assert!(validate_inventory(&changed_a2_precedence).is_err());

    let mut weakened_a2_redaction = inventory.clone();
    weakened_a2_redaction["a2_implementation_receipt"]["secret_rows"][3]["secret_contract"] =
        Value::String("RAW_SECRET_OUTPUT".to_owned());
    assert!(validate_inventory(&weakened_a2_redaction).is_err());

    let mut stale_a2_pin = inventory.clone();
    stale_a2_pin["a2_implementation_receipt"]["source_pin_reconciliation"]["rows"][0]["current_sha256"] =
        Value::String("0".repeat(64));
    assert!(validate_inventory(&stale_a2_pin).is_err());

    let mut stale_maintenance_pin = inventory.clone();
    stale_maintenance_pin["a2_implementation_receipt"]["source_pin_reconciliation"]["format_only_maintenance"]
        ["rows"][0]["current_sha256"] = Value::String("0".repeat(64));
    assert!(validate_inventory(&stale_maintenance_pin).is_err());

    let mut changed_toml_contract = inventory;
    changed_toml_contract["post_a3_provenance_refresh"]["refreshed_paths"][0]["accepted_toml_contract_changed"] =
        Value::Bool(true);
    assert!(validate_inventory(&changed_toml_contract).is_err());
}
