#![allow(missing_docs)]

use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write;
use std::path::{Path, PathBuf};

const CONTRACT_PATH: &str = "artifacts/rust_crate_release_provenance_contract_v1.json";
const INTEGRITY_MANIFEST_PATH: &str =
    "artifacts/rust_crate_release_provenance_integrity_manifest_v1.json";
const FINAL_SIGNOFF_PATH: &str = "artifacts/rust_crate_release_provenance_final_signoff_v1.json";
const DRY_RUN_E2E_LOG_PATH: &str = "artifacts/rust_crate_release_provenance_dry_run_e2e_v1.log";
const FINAL_SIGNOFF_DOC_PATH: &str = "docs/rust_crate_release_provenance_final_signoff.md";
const OPERATOR_DOC_PATH: &str = "docs/rust_crate_release_provenance_artifacts.md";
const POLICY_PATH: &str = "docs/rust_crate_release_provenance_policy.md";
const PROOF_MANIFEST_PATH: &str = "artifacts/proof_lane_manifest_v1.json";
const PROOF_STATUS_PATH: &str = "artifacts/proof_status_snapshot_v1.json";
const PUBLISH_WORKFLOW_PATH: &str = ".github/workflows/publish.yml";
const TEST_PATH: &str = "tests/rust_crate_release_provenance_contract.rs";

const LANE_ID: &str = "rust-crate-release-provenance-contract";
const PROOF_COMMAND: &str = "RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_rust_crate_release_provenance_contract CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 RUSTFLAGS='-D warnings -C debuginfo=0' cargo test -p asupersync --test rust_crate_release_provenance_contract -- --nocapture";
const CLOSEOUT_PROOF_COMMAND: &str = "RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_TARGET_DIR=\"${TMPDIR:-/tmp}/rch_target_rust_crate_release_provenance_contract\" CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 RUSTFLAGS='-D warnings -C debuginfo=0' cargo test -p asupersync --test rust_crate_release_provenance_contract --test proof_lane_manifest_contract --test proof_status_snapshot_contract -- --nocapture";

const REQUIRED_RECORD_FIELDS: &[&str] = &[
    "schema_version",
    "record_id",
    "status",
    "git_head",
    "tag",
    "package",
    "digests.cargo_lock_sha256",
    "digests.cargo_toml_sha256",
    "digests.root_cargo_toml_sha256",
    "cargo_metadata_snapshot",
    "dependency_license_sbom",
    "dry_run_command",
    "dry_run_outcome",
    "package_tarball_sha256",
    "publish_command",
    "publish_outcome",
    "crates_io_visibility_check",
    "integrity_manifest",
    "no_claim_boundaries",
];

const REQUIRED_NO_CLAIM_BOUNDARIES: &[&str] = &[
    "does_not_prove_release_readiness",
    "does_not_prove_runtime_correctness",
    "does_not_prove_workspace_health",
    "does_not_prove_live_crates_io_publication",
    "does_not_prove_real_tarball_integrity",
];

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

fn array<'a>(value: &'a Value, key: &str) -> Result<&'a Vec<Value>, String> {
    value
        .get(key)
        .and_then(Value::as_array)
        .ok_or_else(|| format!("{key} must be an array"))
}

fn string<'a>(value: &'a Value, key: &str) -> Result<&'a str, String> {
    let text = value
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("{key} must be a string"))?;
    if text.trim().is_empty() {
        return Err(format!("{key} must be nonempty"));
    }
    Ok(text)
}

fn bool_field(value: &Value, key: &str) -> Result<bool, String> {
    value
        .get(key)
        .and_then(Value::as_bool)
        .ok_or_else(|| format!("{key} must be a boolean"))
}

fn nested_value<'a>(value: &'a Value, path: &str) -> Option<&'a Value> {
    let mut cursor = value;
    for part in path.split('.') {
        cursor = cursor.get(part)?;
    }
    Some(cursor)
}

fn string_set(value: &Value, key: &str) -> Result<BTreeSet<String>, String> {
    array(value, key)?
        .iter()
        .map(|item| {
            item.as_str()
                .ok_or_else(|| format!("{key} entries must be strings"))
                .map(ToOwned::to_owned)
        })
        .collect::<Result<BTreeSet<_>, _>>()
}

fn sha256_hex(relative: &str) -> String {
    let bytes = std::fs::read(repo_path(relative))
        .unwrap_or_else(|err| panic!("read bytes for {relative}: {err}"));
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let digest = hasher.finalize();
    let mut out = String::with_capacity(digest.len() * 2);
    for byte in digest.iter() {
        write!(&mut out, "{byte:02x}").expect("write to String cannot fail");
    }
    out
}

fn assert_prefixed_sha256(value: &str, context: &str) -> Result<(), String> {
    let Some(hex) = value.strip_prefix("sha256:") else {
        return Err(format!("{context} must start with sha256:"));
    };
    if hex.len() != 64 || !hex.chars().all(|ch| ch.is_ascii_hexdigit()) {
        return Err(format!("{context} must be sha256 plus 64 hex chars"));
    }
    Ok(())
}

fn workflow_publish_packages() -> Vec<String> {
    let workflow = read_repo_file(PUBLISH_WORKFLOW_PATH);
    let mut packages = Vec::new();
    let mut in_crates_array = false;
    for line in workflow.lines() {
        let trimmed = line.trim();
        if trimmed == "crates=(" {
            in_crates_array = true;
            continue;
        }
        if in_crates_array {
            if trimmed == ")" {
                in_crates_array = false;
                continue;
            }
            if !trimmed.is_empty() && !trimmed.starts_with('#') {
                packages.push(trimmed.trim_matches('"').to_string());
            }
            continue;
        }
        if let Some(rest) = trimmed.strip_prefix("publish_if_needed ") {
            let package = rest
                .split_whitespace()
                .next()
                .expect("publish_if_needed package")
                .trim_matches('"');
            if !package.contains('$') {
                packages.push(package.to_string());
            }
        }
    }
    assert!(
        !packages.is_empty(),
        "publish workflow must expose publish_if_needed package calls"
    );
    packages
}

fn workflow_function_body<'a>(workflow: &'a str, function_name: &str) -> &'a str {
    let start_marker = format!("{function_name}() {{");
    let start = workflow
        .find(&start_marker)
        .unwrap_or_else(|| panic!("workflow missing function {function_name}"));
    let rest = &workflow[start..];
    let end = rest
        .find("\n          }\n")
        .unwrap_or_else(|| panic!("workflow function {function_name} missing closing brace"));
    &rest[..end]
}

fn assert_contains_ordered(haystack: &str, needles: &[&str], context: &str) {
    let mut offset = 0;
    for needle in needles {
        let Some(found) = haystack[offset..].find(needle) else {
            panic!("{context}: missing ordered marker {needle}");
        };
        offset += found + needle.len();
    }
}

fn cargo_package_name(manifest_path: &str) -> String {
    let manifest = read_repo_file(manifest_path);
    let mut in_package = false;
    for line in manifest.lines() {
        let trimmed = line.trim();
        if trimmed == "[package]" {
            in_package = true;
            continue;
        }
        if in_package && trimmed.starts_with('[') {
            break;
        }
        if in_package && trimmed.starts_with("name") {
            if let Some((_, value)) = trimmed.split_once('=') {
                return value.trim().trim_matches('"').to_string();
            }
        }
    }
    panic!("{manifest_path}: missing package name");
}

fn fixture_records_by_id(contract: &Value) -> Result<BTreeMap<String, Value>, String> {
    let mut records = BTreeMap::new();
    for record in array(contract, "fixture_records")? {
        let record_id = string(record, "record_id")?.to_string();
        if records.insert(record_id.clone(), record.clone()).is_some() {
            return Err(format!("duplicate fixture record {record_id}"));
        }
    }
    Ok(records)
}

fn validate_surface_inventory(contract: &Value) -> Result<(), String> {
    let workflow_packages = workflow_publish_packages();
    let surface = array(contract, "published_crate_surface")?;
    let contract_packages = surface
        .iter()
        .map(|entry| string(entry, "package").map(ToOwned::to_owned))
        .collect::<Result<Vec<_>, _>>()?;
    if contract_packages != workflow_packages {
        return Err(format!(
            "published_crate_surface does not match publish workflow: {contract_packages:?} != {workflow_packages:?}"
        ));
    }

    for (index, entry) in surface.iter().enumerate() {
        let expected_order = index + 1;
        let publish_order = entry
            .get("publish_order")
            .and_then(Value::as_u64)
            .ok_or_else(|| "publish_order must be a positive integer".to_string())?;
        if publish_order != expected_order as u64 {
            return Err(format!(
                "{}: publish_order must be {expected_order}",
                string(entry, "package")?
            ));
        }
        let manifest_path = string(entry, "manifest_path")?;
        if !repo_path(manifest_path).exists() {
            return Err(format!("{manifest_path} must exist"));
        }
        let cargo_name = cargo_package_name(manifest_path);
        if cargo_name != string(entry, "package")? {
            return Err(format!(
                "{manifest_path}: package name {cargo_name} does not match contract row"
            ));
        }
        string(entry, "role")?;
    }

    Ok(())
}

fn validate_fixture_record(record: &Value) -> Result<(), String> {
    for field in REQUIRED_RECORD_FIELDS {
        if nested_value(record, field).is_none() {
            return Err(format!("{} missing {field}", string(record, "record_id")?));
        }
    }

    if string(record, "schema_version")? != "rust-crate-release-provenance-record-v1" {
        return Err(format!(
            "{} has wrong schema_version",
            string(record, "record_id")?
        ));
    }
    if string(record, "status")? != "fixture_only" {
        return Err(format!(
            "{} must stay fixture_only",
            string(record, "record_id")?
        ));
    }

    let release_mode = string(record, "release_mode_fixture")?;
    if !["dry_run_only", "already_published_noop"].contains(&release_mode) {
        return Err(format!(
            "{} has unknown release mode {release_mode}",
            string(record, "record_id")?
        ));
    }

    let package = record
        .get("package")
        .ok_or_else(|| "package object missing".to_string())?;
    let package_name = string(package, "name")?;
    let manifest_path = string(package, "manifest_path")?;
    if cargo_package_name(manifest_path) != package_name {
        return Err(format!("{manifest_path}: package name drifted"));
    }
    for key in ["version", "role", "edition", "license"] {
        string(package, key)?;
    }
    if package
        .get("publish_order")
        .and_then(Value::as_u64)
        .ok_or_else(|| "package.publish_order must be an integer".to_string())?
        == 0
    {
        return Err("package.publish_order must be positive".to_string());
    }

    let digests = record
        .get("digests")
        .ok_or_else(|| "digests object missing".to_string())?;
    for key in [
        "cargo_lock_sha256",
        "cargo_toml_sha256",
        "root_cargo_toml_sha256",
    ] {
        assert_prefixed_sha256(string(digests, key)?, key)?;
    }

    let sbom_rows = array(
        record
            .get("dependency_license_sbom")
            .ok_or_else(|| "dependency_license_sbom missing".to_string())?,
        "rows",
    )?;
    if sbom_rows.is_empty() {
        return Err("dependency_license_sbom.rows must be nonempty".to_string());
    }

    let dry_run_command = record
        .get("dry_run_command")
        .ok_or_else(|| "dry_run_command missing".to_string())?;
    let dry_command = string(dry_run_command, "command")?;
    if !(dry_command.contains(package_name) && dry_command.contains("--dry-run --locked")) {
        return Err(format!(
            "{} dry-run command must name package and --dry-run --locked",
            string(record, "record_id")?
        ));
    }
    if !bool_field(dry_run_command, "requires_remote_for_direct_main")? {
        return Err("dry-run command must require remote direct-main validation".to_string());
    }
    if !bool_field(dry_run_command, "credentials_redacted")? {
        return Err("dry-run command must redact credentials".to_string());
    }

    let tarball = record
        .get("package_tarball_sha256")
        .ok_or_else(|| "package_tarball_sha256 missing".to_string())?;
    assert_prefixed_sha256(string(tarball, "sha256")?, "package_tarball_sha256.sha256")?;
    if !bool_field(tarball, "fixture_only")? {
        return Err("fixture tarball hashes must stay fixture_only".to_string());
    }

    let publish_command = record
        .get("publish_command")
        .ok_or_else(|| "publish_command missing".to_string())?;
    let publish_command_text = string(publish_command, "command")?;
    if !(publish_command_text.contains(package_name) && publish_command_text.contains("--locked")) {
        return Err("publish command must name package and --locked".to_string());
    }
    if !bool_field(publish_command, "credentials_redacted")?
        || !bool_field(publish_command, "not_executed_in_fixture")?
    {
        return Err("publish command fixture must redact credentials and not execute".to_string());
    }

    let publish_outcome = record
        .get("publish_outcome")
        .ok_or_else(|| "publish_outcome missing".to_string())?;
    if string(publish_outcome, "status")? != release_mode {
        return Err("publish_outcome.status must match release_mode_fixture".to_string());
    }
    if bool_field(publish_outcome, "published")? {
        return Err("fixture records must not claim publication".to_string());
    }

    let integrity = record
        .get("integrity_manifest")
        .ok_or_else(|| "integrity_manifest missing".to_string())?;
    if string(integrity, "path")? != INTEGRITY_MANIFEST_PATH {
        return Err("fixture record must point at companion integrity manifest".to_string());
    }
    if !integrity.get("sha256").is_some_and(Value::is_null)
        || string(integrity, "sha256_status")? != "recorded_in_companion_manifest"
    {
        return Err("fixture integrity manifest must use non-circular sha256_status".to_string());
    }

    let no_claims = string_set(record, "no_claim_boundaries")?;
    for required in REQUIRED_NO_CLAIM_BOUNDARIES {
        if !no_claims.contains(*required) {
            return Err(format!(
                "{} missing no-claim boundary {required}",
                string(record, "record_id")?
            ));
        }
    }

    let supersession = record
        .get("supersession")
        .ok_or_else(|| "supersession missing".to_string())?;
    if string(supersession, "status")? != "current_fixture"
        || !supersession
            .get("successor_record_id")
            .is_some_and(Value::is_null)
    {
        return Err("current fixture records must not supersede by deletion".to_string());
    }

    Ok(())
}

fn validate_integrity_manifest(contract: &Value) -> Result<(), String> {
    let top_integrity = contract
        .get("integrity_manifest")
        .ok_or_else(|| "top-level integrity_manifest missing".to_string())?;
    if string(top_integrity, "path")? != INTEGRITY_MANIFEST_PATH {
        return Err("top-level integrity manifest path drifted".to_string());
    }
    if !bool_field(top_integrity, "self_hash_excluded")? {
        return Err("top-level integrity manifest must exclude self hash".to_string());
    }

    let manifest = json(INTEGRITY_MANIFEST_PATH);
    if string(&manifest, "schema_version")? != "rust-crate-release-provenance-integrity-manifest-v1"
    {
        return Err("integrity manifest schema drifted".to_string());
    }
    if string(&manifest, "source_contract")? != CONTRACT_PATH {
        return Err("integrity manifest source_contract drifted".to_string());
    }
    if !bool_field(&manifest, "self_hash_excluded")? {
        return Err("integrity manifest must exclude self hash".to_string());
    }

    let expected_paths = BTreeSet::from([
        CONTRACT_PATH.to_string(),
        OPERATOR_DOC_PATH.to_string(),
        POLICY_PATH.to_string(),
    ]);
    let entries = array(&manifest, "entries")?;
    let seen_paths = entries
        .iter()
        .map(|entry| string(entry, "path").map(ToOwned::to_owned))
        .collect::<Result<BTreeSet<_>, _>>()?;
    if seen_paths != expected_paths {
        return Err(format!("integrity manifest paths drifted: {seen_paths:?}"));
    }
    for entry in entries {
        let path = string(entry, "path")?;
        let expected = format!("sha256:{}", sha256_hex(path));
        if string(entry, "sha256")? != expected {
            return Err(format!("{path}: integrity digest drifted"));
        }
        string(entry, "role")?;
        string(entry, "citeability")?;
    }

    Ok(())
}

fn validate_contract(contract: &Value) -> Result<(), String> {
    if string(contract, "schema_version")? != "rust-crate-release-provenance-contract-v1" {
        return Err("contract schema_version drifted".to_string());
    }
    if string(contract, "primary_bead")? != "asupersync-release-provenance-core-crates-jpts8n.2" {
        return Err("primary bead drifted".to_string());
    }
    if string(contract, "source_policy")? != POLICY_PATH
        || string(contract, "publish_workflow")? != PUBLISH_WORKFLOW_PATH
    {
        return Err("contract source paths drifted".to_string());
    }

    for path in [
        CONTRACT_PATH,
        INTEGRITY_MANIFEST_PATH,
        OPERATOR_DOC_PATH,
        POLICY_PATH,
        PUBLISH_WORKFLOW_PATH,
    ] {
        if !repo_path(path).exists() {
            return Err(format!("{path} must exist"));
        }
    }

    let required_fields = string_set(contract, "required_record_fields")?;
    for field in REQUIRED_RECORD_FIELDS {
        if !required_fields.contains(*field) {
            return Err(format!("required_record_fields missing {field}"));
        }
    }

    let vocabulary = contract
        .get("status_vocabulary")
        .ok_or_else(|| "status_vocabulary missing".to_string())?;
    for status in [
        "dry_run_only",
        "published",
        "already_published_noop",
        "skipped_token_absent",
        "superseded",
        "fixture_only",
    ] {
        string(vocabulary, status)?;
    }

    validate_surface_inventory(contract)?;
    validate_integrity_manifest(contract)?;

    let records = fixture_records_by_id(contract)?;
    for required in [
        "fixture-asupersync-0.3.4-dry-run",
        "fixture-franken-kernel-0.3.4-already-published",
        "fixture-asupersync-tokio-compat-0.3.4-dry-run",
    ] {
        if !records.contains_key(required) {
            return Err(format!("missing fixture record {required}"));
        }
    }
    let release_modes = records
        .values()
        .map(|record| string(record, "release_mode_fixture").map(ToOwned::to_owned))
        .collect::<Result<BTreeSet<_>, _>>()?;
    for required in ["dry_run_only", "already_published_noop"] {
        if !release_modes.contains(required) {
            return Err(format!("missing fixture release mode {required}"));
        }
    }
    for record in records.values() {
        validate_fixture_record(record)?;
    }

    Ok(())
}

fn validate_final_signoff(signoff: &Value, contract: &Value) -> Result<(), String> {
    if string(signoff, "schema_version")? != "rust-crate-release-provenance-final-signoff-v1" {
        return Err("final signoff schema_version drifted".to_string());
    }
    if string(signoff, "primary_bead")? != "asupersync-release-provenance-core-crates-jpts8n.5"
        || string(signoff, "parent_bead")? != "asupersync-release-provenance-core-crates-jpts8n"
    {
        return Err("final signoff bead mapping drifted".to_string());
    }

    let source_paths = signoff
        .get("source_paths")
        .ok_or_else(|| "source_paths missing".to_string())?;
    for (field, path) in [
        ("final_signoff", FINAL_SIGNOFF_PATH),
        ("dry_run_e2e_log", DRY_RUN_E2E_LOG_PATH),
        ("operator_report", FINAL_SIGNOFF_DOC_PATH),
        ("policy", POLICY_PATH),
        ("artifact_contract", CONTRACT_PATH),
        ("integrity_manifest", INTEGRITY_MANIFEST_PATH),
        ("publish_workflow", PUBLISH_WORKFLOW_PATH),
        ("contract_test", TEST_PATH),
        ("proof_manifest", PROOF_MANIFEST_PATH),
        ("proof_status_snapshot", PROOF_STATUS_PATH),
    ] {
        if string(source_paths, field)? != path {
            return Err(format!("source_paths.{field} drifted"));
        }
        if !repo_path(path).exists() {
            return Err(format!("{path} must exist"));
        }
    }

    let integrity = array(signoff, "artifact_integrity")?;
    let integrity_by_path = integrity
        .iter()
        .map(|entry| string(entry, "path").map(|path| (path.to_string(), entry)))
        .collect::<Result<BTreeMap<_, _>, _>>()?;
    for path in [DRY_RUN_E2E_LOG_PATH, FINAL_SIGNOFF_DOC_PATH] {
        let entry = integrity_by_path
            .get(path)
            .ok_or_else(|| format!("missing artifact_integrity row for {path}"))?;
        let expected = format!("sha256:{}", sha256_hex(path));
        if string(entry, "sha256")? != expected {
            return Err(format!("{path}: final signoff digest drifted"));
        }
        string(entry, "role")?;
    }

    let e2e = signoff
        .get("dry_run_e2e")
        .ok_or_else(|| "dry_run_e2e missing".to_string())?;
    if string(e2e, "execution_mode")? != "deterministic_fixture_no_live_publish" {
        return Err("dry_run_e2e execution mode drifted".to_string());
    }
    if bool_field(e2e, "live_publish_performed")?
        || bool_field(e2e, "cargo_publish_dry_run_performed")?
    {
        return Err(
            "R5 deterministic e2e must not claim live publish or cargo publish --dry-run"
                .to_string(),
        );
    }
    if string(e2e, "package_byte_source")? != "deterministic_fixture_not_real_crate_tarball" {
        return Err("R5 package byte source must remain fixture-only".to_string());
    }
    for status in ["packaged", "skipped", "already_published", "blocked"] {
        if !string_set(e2e, "status_vocabulary")?.contains(status) {
            return Err(format!("dry_run_e2e status vocabulary missing {status}"));
        }
    }

    let outputs = e2e
        .get("artifact_outputs")
        .ok_or_else(|| "artifact_outputs missing".to_string())?;
    for (field, path) in [
        ("json", FINAL_SIGNOFF_PATH),
        ("markdown", FINAL_SIGNOFF_DOC_PATH),
        ("log", DRY_RUN_E2E_LOG_PATH),
    ] {
        if string(outputs, field)? != path {
            return Err(format!("artifact_outputs.{field} drifted"));
        }
    }

    let surface = array(contract, "published_crate_surface")?;
    let results = array(e2e, "per_package_results")?;
    if results.len() != surface.len() {
        return Err("R5 e2e rows must cover every published crate surface".to_string());
    }
    let operator_doc = read_repo_file(FINAL_SIGNOFF_DOC_PATH);
    let e2e_log = read_repo_file(DRY_RUN_E2E_LOG_PATH);
    for (index, (surface_row, result)) in surface.iter().zip(results.iter()).enumerate() {
        let expected_order = index + 1;
        if result
            .get("publish_order")
            .and_then(Value::as_u64)
            .ok_or_else(|| "publish_order must be integer".to_string())?
            != expected_order as u64
        {
            return Err(format!("R5 e2e row {expected_order} publish_order drifted"));
        }
        let package = string(result, "package")?;
        if package != string(surface_row, "package")? {
            return Err(format!("R5 e2e row {expected_order} package drifted"));
        }
        if string(result, "manifest_path")? != string(surface_row, "manifest_path")? {
            return Err(format!("{package}: manifest path drifted in R5 e2e row"));
        }
        if string(result, "status")? != "packaged" {
            return Err(format!(
                "{package}: deterministic R5 fixture must stay packaged"
            ));
        }
        let record_id = string(result, "record_id")?;
        if !(record_id.starts_with("fixture-e2e-") && record_id.ends_with("-0.3.4")) {
            return Err(format!(
                "{package}: record_id must be deterministic fixture id"
            ));
        }
        let package_sha = string(result, "package_tarball_sha256")?;
        assert_prefixed_sha256(package_sha, "package_tarball_sha256")?;
        if bool_field(result, "live_publish_performed")? {
            return Err(format!("{package}: R5 e2e row must not claim live publish"));
        }

        let doc_marker = format!("| {expected_order} | `{package}` | `packaged` | `{record_id}` |");
        if !operator_doc.contains(&doc_marker) {
            return Err(format!("operator report missing row marker {doc_marker}"));
        }
        let log_marker = format!(
            "result[{expected_order}]={package} status=packaged record={record_id} package_sha256={package_sha}"
        );
        if !e2e_log.lines().any(|line| line == log_marker) {
            return Err(format!("e2e log missing result line {log_marker}"));
        }
    }

    let child_evidence = array(signoff, "child_evidence")?;
    let child_by_bead = child_evidence
        .iter()
        .map(|child| string(child, "bead").map(|bead| (bead.to_string(), child)))
        .collect::<Result<BTreeMap<_, _>, _>>()?;
    for suffix in ["1", "2", "3", "4"] {
        let bead = format!("asupersync-release-provenance-core-crates-jpts8n.{suffix}");
        let child = child_by_bead
            .get(&bead)
            .ok_or_else(|| format!("missing child evidence for {bead}"))?;
        if string(child, "status")? != "closed" {
            return Err(format!("{bead} must be closed in final signoff"));
        }
        if array(child, "evidence_paths")?.is_empty() {
            return Err(format!("{bead} must carry evidence paths"));
        }
    }

    let proof_commands = array(signoff, "proof_commands")?;
    let commands_by_label = proof_commands
        .iter()
        .map(|command| string(command, "label").map(|label| (label.to_string(), command)))
        .collect::<Result<BTreeMap<_, _>, _>>()?;
    for (label, expected_command) in [
        ("focused_manifest_lane", PROOF_COMMAND),
        ("closeout_verifier", CLOSEOUT_PROOF_COMMAND),
    ] {
        let command = commands_by_label
            .get(label)
            .ok_or_else(|| format!("missing proof command {label}"))?;
        if string(command, "command")? != expected_command {
            return Err(format!("{label} command drifted"));
        }
        if !bool_field(command, "remote_required")?
            || bool_field(command, "local_fallback_allowed")?
        {
            return Err(format!(
                "{label} must be remote-required with no local fallback"
            ));
        }
    }

    let closeout = signoff
        .get("closeout_requirements")
        .ok_or_else(|| "closeout_requirements missing".to_string())?;
    for field in [
        "agent_mail_handoff_required_before_close",
        "tracker_comment_required_before_close",
        "focused_rch_verifier_required_before_close",
        "parent_epic_close_allowed_after_r5_close",
    ] {
        if !bool_field(closeout, field)? {
            return Err(format!("closeout_requirements.{field} must be true"));
        }
    }
    if !string(closeout, "parent_epic_close_claim")?.contains("not release readiness") {
        return Err("parent epic close claim must preserve release-readiness boundary".to_string());
    }

    let report = signoff
        .get("current_operator_report")
        .ok_or_else(|| "current_operator_report missing".to_string())?;
    if string(report, "final_verdict")? != "yellow_scoped_signoff_complete" {
        return Err("R5 final verdict drifted".to_string());
    }
    if !report.get("first_failing_row").is_some_and(Value::is_null) {
        return Err("R5 final signoff should not hide a failing row".to_string());
    }
    for (field, expected) in [
        ("package_surface_rows", 9),
        ("packaged", 9),
        ("skipped", 0),
        ("already_published", 0),
        ("blocked", 0),
    ] {
        if report.get(field).and_then(Value::as_u64) != Some(expected) {
            return Err(format!("operator report {field} count drifted"));
        }
    }
    if bool_field(report, "live_publish_performed")?
        || bool_field(report, "cargo_publish_dry_run_performed")?
    {
        return Err(
            "operator report must not claim live publish or cargo publish dry-run".to_string(),
        );
    }

    let no_claims = string_set(signoff, "no_claim_boundaries")?;
    for required in [
        "does_not_prove_release_readiness",
        "does_not_prove_runtime_correctness",
        "does_not_prove_broad_workspace_health",
        "does_not_prove_security_audit_completion",
        "does_not_prove_live_crates_io_publication",
        "does_not_prove_real_package_tarball_integrity",
        "does_not_authorize_local_cargo_fallback",
    ] {
        if !no_claims.contains(required) {
            return Err(format!(
                "final signoff missing no-claim boundary {required}"
            ));
        }
    }
    for marker in [
        "yellow_scoped_signoff_complete",
        "does not perform a live crates.io publish",
        "does not prove release readiness",
        "Agent Mail handoff",
    ] {
        if !operator_doc.contains(marker) {
            return Err(format!("operator report missing marker {marker}"));
        }
    }
    for marker in [
        "final_verdict=yellow_scoped_signoff_complete",
        "live_publish=false",
        "cargo_publish_dry_run=false",
        "no_claim=does_not_prove_live_crates_io_publication",
    ] {
        if !e2e_log.contains(marker) {
            return Err(format!("e2e log missing marker {marker}"));
        }
    }

    Ok(())
}

#[test]
fn contract_schema_fixture_records_and_negative_cases_are_checked() {
    let contract = json(CONTRACT_PATH);
    validate_contract(&contract).unwrap_or_else(|error| panic!("{error}"));

    let mut missing_tarball = contract.clone();
    missing_tarball["fixture_records"][0]
        .as_object_mut()
        .expect("fixture object")
        .remove("package_tarball_sha256");
    let error = validate_contract(&missing_tarball).unwrap_err();
    assert!(
        error.contains("package_tarball_sha256"),
        "malformed fixture should fail on missing tarball hash: {error}"
    );

    let mut overclaiming = contract.clone();
    overclaiming["fixture_records"][0]["no_claim_boundaries"]
        .as_array_mut()
        .expect("no_claim_boundaries array")
        .retain(|boundary| boundary.as_str() != Some("does_not_prove_live_crates_io_publication"));
    let error = validate_contract(&overclaiming).unwrap_err();
    assert!(
        error.contains("does_not_prove_live_crates_io_publication"),
        "overclaiming fixture should fail on missing no-claim boundary: {error}"
    );
}

#[test]
fn published_crate_surface_tracks_publish_workflow_order() {
    let contract = json(CONTRACT_PATH);
    let workflow_packages = workflow_publish_packages();
    validate_surface_inventory(&contract).unwrap_or_else(|error| panic!("{error}"));

    let surface_packages = array(&contract, "published_crate_surface")
        .expect("surface rows")
        .iter()
        .map(|entry| string(entry, "package").expect("package").to_string())
        .collect::<Vec<_>>();
    assert_eq!(
        surface_packages, workflow_packages,
        "contract package surface must stay derived from publish_if_needed order"
    );
}

#[test]
fn companion_integrity_manifest_hashes_live_artifacts() {
    let contract = json(CONTRACT_PATH);
    validate_integrity_manifest(&contract).unwrap_or_else(|error| panic!("{error}"));
}

#[test]
fn final_signoff_packet_maps_dry_run_e2e_and_child_evidence() {
    let contract = json(CONTRACT_PATH);
    let signoff = json(FINAL_SIGNOFF_PATH);
    validate_final_signoff(&signoff, &contract).unwrap_or_else(|error| panic!("{error}"));

    let mut overclaiming = signoff.clone();
    overclaiming["dry_run_e2e"]["live_publish_performed"] = Value::Bool(true);
    let error = validate_final_signoff(&overclaiming, &contract).unwrap_err();
    assert!(
        error.contains("live publish"),
        "overclaiming final signoff should reject live publish claim: {error}"
    );

    let mut missing_child = signoff.clone();
    missing_child["child_evidence"]
        .as_array_mut()
        .expect("child evidence array")
        .retain(|child| {
            child.get("bead").and_then(Value::as_str)
                != Some("asupersync-release-provenance-core-crates-jpts8n.3")
        });
    let error = validate_final_signoff(&missing_child, &contract).unwrap_err();
    assert!(
        error.contains("jpts8n.3"),
        "final signoff should fail closed when child evidence disappears: {error}"
    );
}

#[test]
fn publish_workflow_records_and_validates_provenance_before_live_publish() {
    let workflow = read_repo_file(PUBLISH_WORKFLOW_PATH);
    for marker in [
        "RUST_CRATE_PROVENANCE_DIR: artifacts/release_provenance/rust-crates",
        "write_release_provenance_record()",
        "validate_release_provenance_record()",
        "generate_release_provenance_manifest()",
        "Upload Rust crate release provenance",
        "rust-crate-release-provenance",
        "WASM and npm provenance remain separate workflow surfaces.",
        "Generate release lockfile for locked publish",
        "cargo generate-lockfile",
    ] {
        assert!(
            workflow.contains(marker),
            "publish workflow missing provenance gate marker {marker}"
        );
    }

    let publish_body = workflow_function_body(&workflow, "publish_if_needed");
    assert_contains_ordered(
        publish_body,
        &[
            "version_is_published \"$crate\" \"$version\"",
            "write_release_provenance_record \"$crate\" \"$version\" \"already_published_noop\"",
        ],
        "already-published branch must record a structured no-op",
    );
    assert_contains_ordered(
        publish_body,
        &[
            "env CARGO_TARGET_DIR=\"$package_target_dir\" cargo package -p \"$crate\" --locked",
            "package_sha=\"$(sha256_prefixed \"$package_file\")\"",
            "cargo_dry_run_with_target_dir \"$dry_run_target_dir\"",
            "cargo publish -p \"$crate\" --dry-run --locked",
            "write_release_provenance_record \"$crate\" \"$version\" \"dry_run_only\"",
            "validate_release_provenance_record \"$record_path\" \"$crate\" \"$version\" \"$package_sha\"",
            "cargo publish -p \"$crate\" --locked",
            "wait_for_version \"$crate\" \"$version\"",
            "write_release_provenance_record \"$crate\" \"$version\" \"published\"",
        ],
        "prepublish provenance must be validated before live cargo publish",
    );

    let validation_body = workflow_function_body(&workflow, "validate_release_provenance_record");
    for marker in [
        ".dry_run_outcome.status == \"passed\"",
        ".publish_outcome.status == \"dry_run_only\"",
        ".package_tarball_sha256.sha256 == $package_sha",
        "does_not_prove_release_readiness",
    ] {
        assert!(
            validation_body.contains(marker),
            "validation gate missing fail-closed marker {marker}"
        );
    }

    assert!(
        workflow.contains("\"skipped_token_absent\"")
            && workflow.contains("\"not_run_token_absent\""),
        "missing token path must emit structured skip provenance"
    );
    assert!(
        workflow.contains("cargo_dry_run_with_target_dir")
            && workflow.contains("isolated CARGO_TARGET_DIR"),
        "GitHub runner dry-run behavior must document isolated target dirs and rch fallback"
    );
}

#[test]
fn proof_manifest_and_status_rows_are_scoped_to_provenance_contract() {
    let manifest = json(PROOF_MANIFEST_PATH);
    let lanes = array(&manifest, "lanes").expect("manifest lanes");
    let lane = lanes
        .iter()
        .find(|lane| lane.get("lane_id").and_then(Value::as_str) == Some(LANE_ID))
        .expect("missing rust crate release provenance lane");
    assert_eq!(string(lane, "kind").unwrap(), "artifact_contract");
    assert_eq!(
        string(lane, "resource_envelope_class").unwrap(),
        "artifact-contract-medium"
    );
    assert_eq!(string(lane, "command").unwrap(), PROOF_COMMAND);
    assert_eq!(
        string_set(lane, "guarantee_ids").unwrap(),
        BTreeSet::from([LANE_ID.to_string()])
    );
    for required_path in [
        PUBLISH_WORKFLOW_PATH,
        CONTRACT_PATH,
        INTEGRITY_MANIFEST_PATH,
        FINAL_SIGNOFF_PATH,
        DRY_RUN_E2E_LOG_PATH,
        FINAL_SIGNOFF_DOC_PATH,
        OPERATOR_DOC_PATH,
        POLICY_PATH,
        TEST_PATH,
        PROOF_MANIFEST_PATH,
        PROOF_STATUS_PATH,
    ] {
        assert!(
            string_set(lane, "source_paths")
                .unwrap()
                .contains(required_path),
            "lane source_paths must include {required_path}"
        );
    }
    let explicit_not_covered = string(lane, "explicit_not_covered")
        .expect("explicit_not_covered")
        .to_ascii_lowercase();
    for boundary in [
        "release readiness",
        "runtime correctness",
        "broad workspace health",
        "live crates.io publication",
        "real package tarball integrity",
    ] {
        assert!(
            explicit_not_covered.contains(boundary),
            "lane must preserve non-claim boundary {boundary}"
        );
    }
    let proof_reuse = lane
        .get("proof_reuse_policy")
        .expect("lane proof_reuse_policy");
    assert_eq!(
        string_set(proof_reuse, "allowed_claim_scopes").unwrap(),
        BTreeSet::from([LANE_ID.to_string()])
    );
    for broad_scope in [
        "fresh-rch-pass",
        "release-readiness",
        "workspace-health",
        "runtime-correctness",
    ] {
        assert!(
            string_set(proof_reuse, "non_citeable_claim_scopes")
                .unwrap()
                .contains(broad_scope),
            "proof reuse policy must reject {broad_scope}"
        );
    }

    let guarantees = array(&manifest, "guarantees").expect("guarantees");
    let guarantee = guarantees
        .iter()
        .find(|guarantee| guarantee.get("guarantee_id").and_then(Value::as_str) == Some(LANE_ID))
        .expect("missing rust crate release provenance guarantee");
    assert_eq!(
        string_set(guarantee, "lane_ids").unwrap(),
        BTreeSet::from([LANE_ID.to_string()])
    );

    let snapshot = json(PROOF_STATUS_PATH);
    let rows = array(&snapshot, "claim_categories").expect("claim categories");
    let row = rows
        .iter()
        .find(|row| row.get("claim_id").and_then(Value::as_str) == Some(LANE_ID))
        .expect("missing rust crate release provenance status row");
    assert_eq!(string(row, "status").unwrap(), "yellow_scoped");
    assert_eq!(
        string(row, "proof_evidence_status").unwrap(),
        "rerun-required"
    );
    assert_eq!(
        string_set(row, "manifest_guarantee_ids").unwrap(),
        BTreeSet::from([LANE_ID.to_string()])
    );
    assert_eq!(
        string_set(row, "manifest_lane_ids").unwrap(),
        BTreeSet::from([LANE_ID.to_string()])
    );
    assert_eq!(
        string_set(row, "proof_commands").unwrap(),
        BTreeSet::from([PROOF_COMMAND.to_string()])
    );
    assert!(row.get("blocked_frontier").is_some_and(Value::is_null));
    let notes = string(row, "notes").expect("notes").to_ascii_lowercase();
    for boundary in [
        "yellow-scoped",
        "final signoff",
        "deterministic dry-run e2e",
        "does not run cargo publish",
        "release readiness",
        "runtime correctness",
        "broad workspace health",
        "live crates.io publication",
        "real package tarball integrity",
    ] {
        assert!(
            notes.contains(boundary),
            "status row must preserve boundary {boundary}"
        );
    }
}
