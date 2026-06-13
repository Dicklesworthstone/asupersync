#![allow(missing_docs)]

use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write;
use std::path::{Path, PathBuf};

const CONTRACT_PATH: &str = "artifacts/rust_crate_release_provenance_contract_v1.json";
const INTEGRITY_MANIFEST_PATH: &str =
    "artifacts/rust_crate_release_provenance_integrity_manifest_v1.json";
const OPERATOR_DOC_PATH: &str = "docs/rust_crate_release_provenance_artifacts.md";
const POLICY_PATH: &str = "docs/rust_crate_release_provenance_policy.md";
const PROOF_MANIFEST_PATH: &str = "artifacts/proof_lane_manifest_v1.json";
const PROOF_STATUS_PATH: &str = "artifacts/proof_status_snapshot_v1.json";
const PUBLISH_WORKFLOW_PATH: &str = ".github/workflows/publish.yml";
const TEST_PATH: &str = "tests/rust_crate_release_provenance_contract.rs";

const LANE_ID: &str = "rust-crate-release-provenance-contract";
const PROOF_COMMAND: &str = "RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_rust_crate_release_provenance_contract CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 RUSTFLAGS='-D warnings -C debuginfo=0' cargo test -p asupersync --test rust_crate_release_provenance_contract -- --nocapture";

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
    Ok(array(value, key)?
        .iter()
        .map(|item| {
            item.as_str()
                .ok_or_else(|| format!("{key} entries must be strings"))
                .map(ToOwned::to_owned)
        })
        .collect::<Result<BTreeSet<_>, _>>()?)
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
    for line in workflow.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("publish_if_needed ") {
            let package = rest
                .split_whitespace()
                .next()
                .expect("publish_if_needed package");
            packages.push(package.to_string());
        }
    }
    assert!(
        !packages.is_empty(),
        "publish workflow must expose publish_if_needed package calls"
    );
    packages
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
